"""TLS certificates for lookalike domains (issue #10), from Certificate Transparency logs.

Every publicly trusted certificate is recorded in public Certificate Transparency (CT)
logs. Someone who builds a phishing website on a lookalike domain wants HTTPS, so they
request a certificate, and it shows up in the logs, often before the attack starts.

For every registered lookalike found by the lookalike check (#9) we ask a CT search
service which **valid** certificates exist for it:
1. Cert Spotter (api.certspotter.com): fast, indexes new certificates within minutes and
   only lists unexpired certificates. It searches the domain and its subdomains.
2. crt.sh: the backup; often overloaded (HTTP 502) and hours behind with indexing. We ask
   it for unexpired certificates of the exact name only, because its subdomain search
   (%.domain) fails even more often. So the backup can miss a certificate that only
   covers a subdomain (e.g. login.lookalike.be); the finding says which service answered.

Only valid certificates count, whichever service answers, so the result does not depend
on which one was reached. An expired certificate is history; the lookalike domain itself
is already reported by the lookalike check.

Uncertain answers are not reported as "no certificate": when Cert Spotter fails and crt.sh
answers with nothing, crt.sh may simply not have indexed it yet, so that lookalike counts
as not checked. A service that fails three times in a row is skipped for the rest of the
scan (circuit breaker), so a hanging service cannot make a scan take 25 x 30 seconds.

Cert Spotter returns a limited number of certificates per response (more through its
`after` parameter). We read only the first page: one valid certificate is enough for the
finding, and every extra request counts against the free hourly limit. The details then
list the first certificates found.

Without an API key Cert Spotter is for personal or evaluation use with a small hourly
limit, which covers this student project; a real deployment sets CERTSPOTTER_API_KEY.

Only when no lookalike could be checked does the check fail. The phishing module then
still returns the findings of its other checks (data contract 10.3.1).
"""

import http.client
import json
import logging
import os
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from pydantic import ValidationError

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.phishing.constants import MODULE

log = logging.getLogger(__name__)

FINDING_TYPE = "lookalike_certificate"
CERTSPOTTER = "Cert Spotter"
CRTSH = "crt.sh"
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true"
    "&expand=dns_names&expand=issuer"
)
CRTSH_URL = "https://crt.sh/?q={}&output=json&exclude=expired"
TIMEOUT_SECONDS = 30
# Keep the number of requests to the free services small (fair use)
MAX_LOOKALIKES = 25
MAX_CERTIFICATES_IN_DETAILS = 5
# A service that fails this many times in a row is skipped for the rest of the scan
MAX_FAILURES_IN_A_ROW = 3
USER_AGENT = "QN-Sentry certificate check"


class CertificateLookupFailed(Exception):
    """One domain could not be checked reliably."""


@dataclass(frozen=True)
class Certificate:
    names: tuple[str, ...]
    issuer: str
    not_before: datetime
    not_after: datetime
    reference: str  # link to the certificate
    source: str  # which CT service found it


@dataclass
class CircuitBreaker:
    """Skips a service for the rest of the scan after MAX_FAILURES_IN_A_ROW failures."""

    failures: dict[str, int] = field(default_factory=dict)

    def available(self, service: str) -> bool:
        return self.failures.get(service, 0) < MAX_FAILURES_IN_A_ROW

    def succeeded(self, service: str) -> None:
        self.failures[service] = 0

    def failed(self, service: str) -> None:
        self.failures[service] = self.failures.get(service, 0) + 1


def configured_api_key() -> str | None:
    """CERTSPOTTER_API_KEY from Settings; the command-line tool has no database settings,
    so it falls back to the environment."""
    try:
        from qnsentry.config import settings
    except ValidationError:
        return os.environ.get("CERTSPOTTER_API_KEY") or None
    return settings.certspotter_api_key


def find_lookalike_certificates(
    lookalikes: list[Finding],
    *,
    now: datetime | None = None,
    api_key: str | None = None,
    warn: Callable[[str], None] = lambda message: None,
) -> list[Finding]:
    """One finding per lookalike domain that has a valid certificate in the CT logs.

    Lookalikes that could not be checked, and the ones above MAX_LOOKALIKES, are reported
    to `warn` as a count (data contract 10.3.1).
    """
    now = now or datetime.now(UTC)
    registered = [f for f in lookalikes if f.type == "lookalike_domain"]
    domains = registered[:MAX_LOOKALIKES]
    breaker = CircuitBreaker()
    findings: list[Finding] = []
    failed: list[str] = []
    for lookalike in domains:
        try:
            certificates = certificates_for(lookalike.asset, breaker=breaker, api_key=api_key)
        except CertificateLookupFailed as error:
            log.warning("Certificate lookup for %s failed: %s", lookalike.asset, error)
            failed.append(f"{lookalike.asset}: {error}")
            continue
        valid = [c for c in certificates if c.not_after > now]
        if valid:
            findings.append(to_finding(lookalike, valid))
    if domains and len(failed) == len(domains):
        raise RuntimeError(f"Certificate Transparency could not be searched reliably: {failed[0]}")
    if failed:
        warn(
            f"{len(failed)} of {len(domains)} lookalike domain(s) could not be checked for certificates, "
            "so certificates for them may have been missed"
        )
    if len(registered) > MAX_LOOKALIKES:
        warn(
            f"Only the first {MAX_LOOKALIKES} of {len(registered)} lookalike domains were checked for "
            "certificates (those that can receive email first)"
        )
    return findings


def certificates_for(
    domain: str, *, breaker: CircuitBreaker | None = None, api_key: str | None = None
) -> list[Certificate]:
    """Unexpired certificates for `domain`: from Cert Spotter, or crt.sh as the backup."""
    breaker = breaker or CircuitBreaker()
    errors: list[str] = []

    if breaker.available(CERTSPOTTER):
        try:
            certificates = from_certspotter(domain, api_key=api_key)
        # Network and HTTP errors, also while reading the answer (IncompleteRead is an
        # HTTPException, not an OSError), and JSON or format errors
        except (OSError, http.client.HTTPException, ValueError, KeyError) as error:
            breaker.failed(CERTSPOTTER)
            errors.append(f"{CERTSPOTTER}: {error}")
        else:
            breaker.succeeded(CERTSPOTTER)
            return certificates
    else:
        errors.append(f"{CERTSPOTTER}: skipped after {MAX_FAILURES_IN_A_ROW} failures in a row")

    if not breaker.available(CRTSH):
        errors.append(f"{CRTSH}: skipped after {MAX_FAILURES_IN_A_ROW} failures in a row")
        raise CertificateLookupFailed("; ".join(errors))
    try:
        certificates = from_crtsh(domain)
    except (OSError, http.client.HTTPException, ValueError, KeyError) as error:
        breaker.failed(CRTSH)
        errors.append(f"{CRTSH}: {error}")
        raise CertificateLookupFailed("; ".join(errors)) from error
    breaker.succeeded(CRTSH)
    if not certificates:
        # crt.sh can be hours behind: an empty answer from the backup is no proof
        errors.append(f"{CRTSH} found none, but it can take hours to index new certificates")
        raise CertificateLookupFailed("; ".join(errors))
    return certificates


def from_certspotter(domain: str, *, api_key: str | None = None) -> list[Certificate]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    return parse_certspotter(_get_json(CERTSPOTTER_URL.format(quote(domain)), headers))


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
            source=CERTSPOTTER,
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
            source=CRTSH,
        )
        for entry in data
    )


def to_finding(lookalike: Finding, certificates: list[Certificate]) -> Finding:
    """A finding for a lookalike with valid certificates."""
    name = lookalike.asset
    newest = sorted(certificates, key=lambda c: c.not_before, reverse=True)
    latest = newest[0]
    issued = f"issued by {latest.issuer} on {latest.not_before:%Y-%m-%d}"

    if lookalike.severity == Severity.INFO:
        # The lookalike check found that the company registered this domain itself
        severity = Severity.INFO
        title = f"TLS certificate for the company's own lookalike domain {name}"
        description = (
            f"There is a valid certificate for {name} ({issued}), but this lookalike domain appears "
            "to be registered by the company itself, so it is most likely used on purpose."
        )
    else:
        severity = Severity.HIGH
        title = f"TLS certificate issued for lookalike domain {name}"
        description = (
            f"A valid certificate exists for the lookalike domain {name} ({issued}). A certificate lets "
            "a website on that domain use HTTPS and show the padlock, so a phishing site looks "
            "trustworthy to employees and customers. It usually means a website is being set up "
            "on the domain. Check who owns it and consider a takedown request."
        )

    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=name,
        details={
            "source": latest.source,
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


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    )
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
