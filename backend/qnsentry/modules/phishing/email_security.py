"""Email security of the client's own domain (issue #29): SPF, DMARC and DKIM.

Without these DNS records, or with weak ones, anyone can send email that appears to
come from the company's own domain (email spoofing). That makes phishing aimed at
employees and customers far more convincing.

- SPF (TXT on the domain): which servers may send mail for the domain
- DMARC (TXT on _dmarc.<domain>): what a receiving mail server must do with mail that
  fails the checks; only p=quarantine and p=reject actually stop spoofed mail
- DKIM (TXT on <selector>._domainkey.<domain>): public keys to verify signed mail.
  Selectors cannot be listed through DNS, so only common selectors are checked.

The evaluate_* functions only interpret record text, so they are tested without network.
"""

import logging
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding

log = logging.getLogger(__name__)

MODULE = "phishing"
FINDING_TYPE = "email_security"
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail")


class LookupFailed(Exception):
    """A DNS lookup gave no usable answer (timeout, server failure), so the result is unknown."""


@dataclass
class SpfResult:
    findings: list[Finding] = field(default_factory=list)
    # True when SPF does not stop anyone: missing, or explicitly allowing every server
    allows_everyone: bool = False


def check_email_security(
    domain: str, *, nameservers: list[str] | None = None, timeout: float = 5.0
) -> list[Finding]:
    """SPF, DMARC and DKIM findings for `domain`.

    A failing lookup skips only that check (data contract 10.3.1: partial failure).
    If SPF and DMARC both fail, the resolver is unusable and the function raises.
    """
    resolver = _resolver(nameservers, timeout)
    findings: list[Finding] = []
    failed: list[str] = []

    spf = SpfResult()
    try:
        spf = evaluate_spf(domain, txt_records(resolver, domain))
        findings += spf.findings
    except LookupFailed as e:
        log.warning("SPF check of %s skipped: %s", domain, e)
        failed.append("SPF")

    try:
        dmarc_records = txt_records(resolver, f"_dmarc.{domain}")
        findings += evaluate_dmarc(domain, dmarc_records, spf_allows_everyone=spf.allows_everyone)
    except LookupFailed as e:
        log.warning("DMARC check of %s skipped: %s", domain, e)
        failed.append("DMARC")

    if len(failed) == 2:
        # Both lookups failed, so the resolver is not answering: stop before trying
        # every DKIM selector, which would only add one timeout per selector
        raise RuntimeError(f"Email security of {domain} could not be checked: the SPF and DMARC lookups failed")

    try:
        findings += evaluate_dkim(domain, dkim_keys(resolver, domain))
    except LookupFailed as e:
        log.warning("DKIM check of %s skipped: %s", domain, e)

    return findings


# ---------- DNS lookups ----------


def txt_records(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    """All TXT records of `name` as text; [] when the name or record does not exist."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        raise LookupFailed(f"{name}: {type(e).__name__}") from e
    # A TXT record can be split into several strings of at most 255 characters
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]


def dkim_keys(resolver: dns.resolver.Resolver, domain: str) -> dict[str, str]:
    """DKIM records found per selector. Raises only when every selector lookup failed."""
    found: dict[str, str] = {}
    failures = 0
    for selector in DKIM_SELECTORS:
        try:
            records = txt_records(resolver, f"{selector}._domainkey.{domain}")
        except LookupFailed:
            failures += 1
            continue
        for record in records:
            if _is_dkim_key(record):
                found[selector] = record
                break
    if failures == len(DKIM_SELECTORS):
        raise LookupFailed(f"every DKIM selector lookup for {domain} failed")
    return found


# ---------- Interpretation ----------


def evaluate_spf(domain: str, txt: list[str]) -> SpfResult:
    spf_records = [r for r in txt if r.lower().startswith("v=spf1")]

    if not spf_records:
        return SpfResult(
            [
                _finding(
                    domain,
                    f"No SPF record on {domain}",
                    "The domain does not say which servers may send its email, so receiving mail "
                    "servers cannot recognise mail from other servers as fake. Add an SPF record; a "
                    "domain that sends no email at all can use 'v=spf1 -all'.",
                    Severity.MEDIUM,
                    {"check": "spf", "record": None},
                )
            ],
            allows_everyone=True,
        )

    if len(spf_records) > 1:
        return SpfResult(
            [
                _finding(
                    domain,
                    f"Multiple SPF records on {domain}",
                    "The domain has more than one SPF record. Receiving mail servers treat that as "
                    "an error and ignore SPF, so it does not protect against spoofed email. Merge "
                    "them into one record.",
                    Severity.MEDIUM,
                    {"check": "spf", "records": spf_records},
                )
            ]
        )

    record = spf_records[0]
    qualifier = spf_all_qualifier(record)
    details = {"check": "spf", "record": record, "all": qualifier}

    if qualifier in ("+all", "all"):
        return SpfResult(
            [
                _finding(
                    domain,
                    f"SPF record allows every server to send email for {domain}",
                    f"The SPF record ends in '{qualifier}', which explicitly authorises every server "
                    "in the world to send email as this domain. The domain can be spoofed and the "
                    "fake mail even passes the SPF check. Replace it with '-all' and list only the "
                    "real mail servers.",
                    Severity.HIGH,
                    details,
                )
            ],
            allows_everyone=True,
        )
    if qualifier == "~all":
        return SpfResult(
            [
                _finding(
                    domain,
                    f"Weak SPF policy on {domain} (~all)",
                    "Mail from servers that are not listed only 'soft fails': receiving mail servers "
                    "are asked to be suspicious but usually still deliver it. On its own this does "
                    "not stop spoofing; a strict DMARC policy or '-all' does.",
                    Severity.LOW,
                    details,
                )
            ]
        )
    if qualifier == "-all":
        return SpfResult()
    if qualifier is None and "redirect=" in record.lower():
        # The policy lives in another domain's record; following it is out of scope for now
        return SpfResult()

    # ?all, or no 'all' at all: the result for unlisted servers is "neutral"
    return SpfResult(
        [
            _finding(
                domain,
                f"SPF record on {domain} does not reject other servers",
                "The SPF record does not end in '-all', so mail from servers that are not listed is "
                "treated as neutral instead of fake. The domain can be spoofed. End the record with "
                "'-all'.",
                Severity.MEDIUM,
                details,
            )
        ]
    )


def spf_all_qualifier(record: str) -> str | None:
    """The 'all' mechanism at the end of an SPF record: '+all', 'all', '-all', '~all', '?all' or None."""
    for term in record.lower().split():
        if term.lstrip("+-~?") == "all":
            return term
    return None


def parse_dmarc(record: str) -> dict[str, str]:
    """'v=DMARC1; p=none; pct=100' -> {'v': 'DMARC1', 'p': 'none', 'pct': '100'}"""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def evaluate_dmarc(domain: str, txt: list[str], *, spf_allows_everyone: bool = False) -> list[Finding]:
    records = [r for r in txt if r.replace(" ", "").lower().startswith("v=dmarc1")]
    # Spoofing is worst when neither SPF nor DMARC stops it (open question 10.6: combinations)
    unprotected = Severity.HIGH if spf_allows_everyone else Severity.MEDIUM
    spf_note = (
        " SPF does not stop spoofed mail either, so nothing on this domain does."
        if spf_allows_everyone
        else ""
    )

    if not records:
        return [
            _finding(
                domain,
                f"No DMARC record on {domain}",
                "Without DMARC, receiving mail servers are not told to block mail that fails the SPF "
                "and DKIM checks, so email that appears to come from this domain is usually "
                f"delivered. The domain can be spoofed.{spf_note} Add a DMARC record with "
                "'p=quarantine' or 'p=reject'.",
                unprotected,
                {"check": "dmarc", "record": None},
            )
        ]

    if len(records) > 1:
        return [
            _finding(
                domain,
                f"Multiple DMARC records on {domain}",
                "The domain has more than one DMARC record. Receiving mail servers then ignore DMARC "
                f"completely, so the domain can be spoofed.{spf_note} Keep one record.",
                unprotected,
                {"check": "dmarc", "records": records},
            )
        ]

    record = records[0]
    tags = parse_dmarc(record)
    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    details = {"check": "dmarc", "record": record, "policy": policy or None, "pct": pct}

    if policy == "none":
        return [
            _finding(
                domain,
                f"DMARC policy p=none on {domain}: spoofed email is delivered",
                "The DMARC policy 'p=none' only asks for reports: receiving mail servers are told to "
                f"deliver mail that fails the checks anyway. The domain can be spoofed.{spf_note} "
                "Change the policy to 'p=quarantine' or 'p=reject'.",
                unprotected,
                details,
            )
        ]
    if policy == "quarantine":
        return [
            _finding(
                domain,
                f"DMARC policy p=quarantine on {domain}: spoofed email goes to spam",
                "Mail that fails the checks is put in the spam folder instead of being rejected. "
                "Spoofing is mostly stopped, but fake mail can still reach users who check their "
                "spam folder. 'p=reject' blocks it completely.",
                Severity.LOW,
                details,
            )
        ]
    if policy == "reject":
        if pct != "100":
            return [
                _finding(
                    domain,
                    f"DMARC policy on {domain} applies to only {pct}% of email",
                    f"The policy 'p=reject' is set, but 'pct={pct}' applies it to only part of the "
                    "mail that fails the checks; the rest is delivered. Remove 'pct' or set it to 100.",
                    Severity.LOW,
                    details,
                )
            ]
        return []

    return [
        _finding(
            domain,
            f"Invalid DMARC record on {domain}",
            "The DMARC record has no valid policy ('p=none', 'quarantine' or 'reject'), so receiving "
            f"mail servers ignore it and the domain can be spoofed.{spf_note}",
            unprotected,
            details,
        )
    ]


def evaluate_dkim(domain: str, keys: dict[str, str]) -> list[Finding]:
    checked = list(DKIM_SELECTORS)
    if keys:
        selectors = ", ".join(sorted(keys))
        return [
            _finding(
                domain,
                f"DKIM keys found on {domain} ({selectors})",
                "The domain publishes DKIM keys, so receiving mail servers can verify that its mail "
                "is signed by the domain. Together with a strict DMARC policy this stops spoofing.",
                Severity.INFO,
                {"check": "dkim", "selectors_found": sorted(keys), "selectors_checked": checked},
            )
        ]
    return [
        _finding(
            domain,
            f"No DKIM key found on {domain} for common selectors",
            "No DKIM key was found under the usual names. Without DKIM, receiving mail servers "
            "cannot verify that mail was really signed by this domain, and protection against "
            "spoofing depends on SPF alone, which breaks when mail is forwarded. The domain may use "
            "a custom selector that cannot be discovered through DNS, so check the mail provider's "
            "settings.",
            Severity.LOW,
            {"check": "dkim", "selectors_found": [], "selectors_checked": checked},
        )
    ]


# ---------- Helpers ----------


def _finding(domain: str, title: str, description: str, severity: Severity, details: dict) -> Finding:
    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=domain,
        details=details,
    )


def _is_dkim_key(record: str) -> bool:
    # DKIM uses the same "tag=value;" syntax as DMARC. The key is in p=; an empty p= means revoked.
    return bool(parse_dmarc(record).get("p"))


def _resolver(nameservers: list[str] | None, timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver
