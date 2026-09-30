"""TLS certificates for lookalike domains (issue #10), from Certificate Transparency logs.

Every publicly trusted certificate is recorded in public Certificate Transparency (CT)
logs. Someone who builds a phishing website on a lookalike domain wants HTTPS, so they
request a certificate, and it shows up in the logs, often before the attack starts.

For every registered lookalike found by the lookalike check (#9) we ask a CT search
service which certificates exist for it:
1. Cert Spotter (api.certspotter.com): fast and indexes new certificates within minutes
2. crt.sh: the backup; it is often overloaded (HTTP 502) and slower to index

Only when both fail for every lookalike does the check fail. The phishing module then
still returns the findings of its other checks (data contract 10.3.1).
"""

import json
import logging
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.phishing.constants import MODULE

log = logging.getLogger(__name__)

FINDING_TYPE = "lookalike_certificate"
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true"
    "&expand=dns_names&expand=issuer"
)
CRTSH_URL = "https://crt.sh/?q={}&output=json"
TIMEOUT_SECONDS = 30
# Keep the number of requests to the free services small (fair use)
MAX_LOOKALIKES = 25
MAX_CERTIFICATES_IN_DETAILS = 5
USER_AGENT = "QN-Sentry certificate check"


class CertificateLookupFailed(Exception):
    """No CT service could be asked about one domain."""


@dataclass(frozen=True)
class Certificate:
    names: tuple[str, ...]
    issuer: str
    not_before: datetime
    not_after: datetime
    reference: str  # link to the certificate
    source: str  # which CT service found it


def find_lookalike_certificates(lookalikes: list[Finding], *, now: datetime | None = None) -> list[Finding]:
    """One finding per lookalike domain that has certificates in the CT logs."""
    now = now or datetime.now(UTC)
    domains = [f for f in lookalikes if f.type == "lookalike_domain"][:MAX_LOOKALIKES]

    findings: list[Finding] = []
    failed: list[str] = []
    for lookalike in domains:
        try:
            certificates = certificates_for(lookalike.asset)
        except CertificateLookupFailed as error:
            log.warning("Certificate lookup for %s failed: %s", lookalike.asset, error)
            failed.append(lookalike.asset)
            continue
        if certificates:
            findings.append(to_finding(lookalike, certificates, now))

    if domains and len(failed) == len(domains):
        raise RuntimeError("Certificate Transparency could not be searched: Cert Spotter and crt.sh both failed")
    return findings


def certificates_for(domain: str) -> list[Certificate]:
    """Certificates for `domain` and its subdomains, from the first service that answers."""
    errors = []
    for name, fetch in (("Cert Spotter", from_certspotter), ("crt.sh", from_crtsh)):
        try:
            return fetch(domain)
        except (OSError, ValueError, KeyError) as error:  # network, HTTP, JSON or format errors
            errors.append(f"{name}: {error}")
    raise CertificateLookupFailed("; ".join(errors))


def from_certspotter(domain: str) -> list[Certificate]:
    return parse_certspotter(_get_json(CERTSPOTTER_URL.format(quote(domain))))


def from_crtsh(domain: str) -> list[Certificate]:
    return parse_crtsh(_get_json(CRTSH_URL.format(quote(domain))))


def parse_certspotter(data: list[dict[str, Any]]) -> list[Certificate]:
    return _unique(
        Certificate(
            names=tuple(sorted(entry["dns_names"])),
            issuer=entry["issuer"].get("friendly_name") or entry["issuer"]["name"],
            not_before=_date(entry["not_before"]),
            not_after=_date(entry["not_after"]),
            # Cert Spotter has no public page per certificate; crt.sh can look it up by fingerprint
            reference=f"https://crt.sh/?sha256={entry['cert_sha256']}",
            source="Cert Spotter",
        )
        for entry in data
    )


def parse_crtsh(data: list[dict[str, Any]]) -> list[Certificate]:
    # crt.sh lists both the precertificate and the final certificate: _unique merges them
    return _unique(
        Certificate(
            names=tuple(sorted(set(entry["name_value"].lower().split("\n")))),
            issuer=_organisation(entry["issuer_name"]),
            not_before=_date(entry["not_before"]),
            not_after=_date(entry["not_after"]),
            reference=f"https://crt.sh/?id={entry['id']}",
            source="crt.sh",
        )
        for entry in data
    )


def to_finding(lookalike: Finding, certificates: list[Certificate], now: datetime) -> Finding:
    name = lookalike.asset
    newest = sorted(certificates, key=lambda c: c.not_before, reverse=True)
    valid = [c for c in newest if c.not_after > now]
    latest = newest[0]
    issued = f"issued by {latest.issuer} on {latest.not_before:%Y-%m-%d}"

    if lookalike.severity == Severity.INFO:
        # The lookalike check found that the company registered this domain itself
        severity = Severity.INFO
        title = f"TLS certificate for the company's own lookalike domain {name}"
        description = (
            f"There is a certificate for {name} ({issued}), but this lookalike domain appears to be "
            "registered by the company itself, so it is most likely used on purpose."
        )
    elif valid:
        severity = Severity.HIGH
        title = f"TLS certificate issued for lookalike domain {name}"
        description = (
            f"A valid certificate exists for the lookalike domain {name} ({issued}). A certificate lets "
            "a website on that domain use HTTPS and show the padlock, so a phishing site looks "
            "trustworthy to employees and customers. It usually means a website is being set up "
            "on the domain. Check who owns it and consider a takedown request."
        )
    else:
        severity = Severity.MEDIUM
        title = f"Expired TLS certificate for lookalike domain {name}"
        description = (
            f"The lookalike domain {name} had a certificate ({issued}), which has expired. The domain "
            "was used for a website before and can be used again at any time."
        )

    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=name,
        details={
            "valid_now": bool(valid),
            "certificate_count": len(newest),
            "certificates": [
                {
                    "names": list(c.names),
                    "issuer": c.issuer,
                    "not_before": c.not_before.isoformat(),
                    "not_after": c.not_after.isoformat(),
                    "reference": c.reference,
                    "source": c.source,
                }
                for c in newest[:MAX_CERTIFICATES_IN_DETAILS]
            ],
        },
    )


# ---------- Helpers ----------


def _get_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def _date(value: str) -> datetime:
    """'2026-09-30T06:27:21Z' (Cert Spotter) or '2026-09-30T06:27:21' (crt.sh) -> aware UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _organisation(issuer_name: str) -> str:
    """'C=US, O=Let's Encrypt, CN=YR1' -> "Let's Encrypt" """
    for part in issuer_name.split(", "):
        if part.startswith("O="):
            return part[2:].strip('"')
    return issuer_name


def _unique(certificates) -> list[Certificate]:
    seen: dict[tuple, Certificate] = {}
    for cert in certificates:
        seen.setdefault((cert.names, cert.not_before, cert.not_after), cert)
    return list(seen.values())
