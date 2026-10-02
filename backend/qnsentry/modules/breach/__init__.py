"""Employee Breach Exposure: business email addresses that appear in known data breaches.

The addresses come from the scan context, filled by the Metadata module (#8): addresses
published on the website. Addresses derived from author names and the email convention
are added in #12. Until the Metadata module exists, the context has no addresses and this
module returns no findings.
"""

import logging
from collections.abc import Callable

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.breach.sources import (
    FABRICATED,
    MALWARE,
    SPAM_LIST,
    Breach,
    BreachSource,
    LookupUnavailable,
    get_breach_source,
)

log = logging.getLogger(__name__)

MODULE = "breach"
FINDING_TYPE = "breached_email"

# Exposed data that lets an attacker log in or commit fraud: a breach with any of these is high
SENSITIVE_DATA = {
    "Passwords",
    "Password hints",
    "Security questions and answers",
    "Credit cards",
    "Bank account numbers",
}
# A breach that exposed nothing but the address itself is low
ONLY_ADDRESS = {"Email addresses"}


class BreachModule(Module):
    name = MODULE

    def __init__(self, source_factory: Callable[[], BreachSource] = get_breach_source) -> None:
        # The source is created when a scan runs, so configuration changes need no restart
        self.source_factory = source_factory

    def run(self, context: ScanContext) -> list[Finding]:
        source = self.source_factory()
        emails = sorted({e.strip().lower() for e in context.emails if e.strip()})
        findings = []
        skipped = []
        for email in emails:
            try:
                breaches = source.lookup(email)
            except LookupUnavailable as error:
                # Skip only this address and keep what the others found (contract 10.3.1).
                # The address itself is not logged: it is personal data.
                log.warning("Breach lookup of one address skipped: %s", error)
                skipped.append(str(error))
                continue
            finding = to_finding(email, breaches, origin="found publicly", source=source)
            if finding:
                findings.append(finding)
        if emails and len(skipped) == len(emails):
            raise RuntimeError(f"No address could be checked: {skipped[0]}")
        if skipped:
            # Without a warning, a skipped address would look the same as a clean one (#32).
            # A count, not the addresses: warnings are shown in the dashboard and the report.
            context.warn(
                f"{len(skipped)} of {len(emails)} email address(es) could not be checked against "
                "data breaches, so breaches of those addresses may have been missed"
            )
        return findings


def to_finding(
    email: str, breaches: list[Breach], origin: str, source: BreachSource | None = None
) -> Finding | None:
    """One finding for an address, or None when only fabricated breaches remain."""
    # A fabricated breach is probably fake data: reporting it would cause needless alarm
    breaches = [b for b in breaches if FABRICATED not in b.flags]
    if not breaches:
        return None
    exposed = sorted({data for breach in breaches for data in breach.data_classes})
    # A spam list is a list of addresses, not a compromise: it never raises the severity
    compromised = [b for b in breaches if SPAM_LIST not in b.flags]
    sensitive = sorted({d for b in compromised for d in b.data_classes} & SENSITIVE_DATA)
    malware = [b.name for b in breaches if MALWARE in b.flags]
    count = len(breaches)
    title = f"{email} appears in {count} data breach{'es' if count != 1 else ''}"

    if malware:
        severity = Severity.HIGH
        description = (
            "This business email address appears in data stolen by malware "
            f"({', '.join(malware)}): the login details were taken from a device the employee "
            "used, not from a website. Have that device checked for malware, change the passwords "
            "that were used on it and turn on multi-factor authentication."
        )
    elif sensitive:
        severity = Severity.HIGH
        description = (
            f"This business email address appears in known data breaches that exposed "
            f"{', '.join(s.lower() for s in sensitive)}. If the employee reuses that password for "
            "company accounts, an attacker can try it on the company's email, VPN or other "
            "systems (credential stuffing). Ask the employee to change the password everywhere it "
            "was used and turn on multi-factor authentication."
        )
    elif not compromised or {d for b in compromised for d in b.data_classes} <= ONLY_ADDRESS:
        # Only the address itself leaked (e.g. a spam list): it barely helps an attacker
        severity = Severity.LOW
        description = (
            "This business email address appears in a leaked list of email addresses. Nothing "
            "else about the employee leaked, but the address is known to be real, so it will "
            "receive more spam and phishing."
        )
    else:
        severity = Severity.MEDIUM
        description = (
            "This business email address appears in known data breaches. No passwords were "
            "exposed, but attackers know the address is real and can use the leaked details to "
            "make phishing emails more convincing."
        )
    if source and source.note:
        description += f" {source.note}"

    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=email,
        details={
            "origin": origin,
            # Only name, date and the kinds of data: never the leaked data itself (GDPR)
            "breaches": [
                {"name": b.name, "date": b.date, "data": list(b.data_classes), "flags": sorted(b.flags)}
                for b in sorted(breaches, key=lambda b: b.date, reverse=True)
            ],
            "exposed_data": exposed,
            **({"source": source.attribution} if source and source.attribution else {}),
        },
    )
