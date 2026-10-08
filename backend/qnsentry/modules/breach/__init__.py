"""Employee Breach Exposure: business email addresses that appear in known data breaches.

Two kinds of addresses are checked, both from the scan context filled by the Metadata
module (#8):
- published: the addresses of the client's domain on its website;
- derived (#12): for the people named in the metadata of public documents who have no
  published address, the address the company's naming convention gives them. An attacker
  does exactly this, so an employee whose address was never published can still be exposed.

Only addresses that appear in a breach end up in a finding; the other derived addresses
are not stored anywhere (data minimisation).
"""

import logging
from collections.abc import Callable

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.names import JOINED, SEPARATED, local_part
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

PUBLISHED = "found publicly"
DERIVED = "derived"


def derived_addresses(context: ScanContext) -> dict[str, str]:
    """{address: name} for the people without a published address, in the company's convention.

    Without a detected convention nothing is derived: a guess without evidence would check
    addresses that probably do not exist. When the style of multi-word last names is not
    known, both are tried (contract 10.4.3); for other names both styles give the same
    address, so nothing is looked up twice.
    """
    if not context.email_convention:
        return {}
    published = {e.strip().lower() for e in context.emails}
    styles = [context.last_name_style] if context.last_name_style else [JOINED, SEPARATED]
    derived: dict[str, str] = {}
    for name in context.person_names:
        for style in styles:
            part = local_part(name, context.email_convention, style)
            if not part:
                continue
            address = f"{part}@{context.domain}".lower()
            if address not in published and address not in derived:
                derived[address] = name
    return derived


class BreachModule(Module):
    name = MODULE

    def __init__(self, source_factory: Callable[[], BreachSource] = get_breach_source) -> None:
        # The source is created when a scan runs, so configuration changes need no restart
        self.source_factory = source_factory

    def run(self, context: ScanContext) -> list[Finding]:
        source = self.source_factory()
        published = sorted({e.strip().lower() for e in context.emails if e.strip()})
        derived = derived_addresses(context)
        to_check = [(email, None) for email in published] + sorted(derived.items())
        emails = [email for email, _ in to_check]
        findings = []
        skipped = []
        for email, name in to_check:
            try:
                breaches = source.lookup(email)
            except LookupUnavailable as error:
                # Skip only this address and keep what the others found (contract 10.3.1).
                # The address itself is not logged: it is personal data.
                log.warning("Breach lookup of one address skipped: %s", error)
                skipped.append(str(error))
                continue
            finding = to_finding(
                email,
                breaches,
                origin=DERIVED if name else PUBLISHED,
                source=source,
                derived_from=name,
                convention=context.email_convention if name else None,
            )
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
    email: str,
    breaches: list[Breach],
    origin: str,
    source: BreachSource | None = None,
    derived_from: str | None = None,
    convention: str | None = None,
) -> Finding | None:
    """One finding for an address, or None when only fabricated breaches remain.

    For a derived address, `derived_from` is the name it was derived from and
    `convention` the naming convention that was applied.
    """
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
    if derived_from:
        description += (
            f" This address was not published: QN-Sentry derived it from the name {derived_from} in "
            f"the metadata of a public document and the company's address pattern ({convention}), "
            "as an attacker would."
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
            **({"derived_from": derived_from, "convention": convention} if derived_from else {}),
            # Only name, date and the kinds of data: never the leaked data itself (GDPR)
            "breaches": [
                {"name": b.name, "date": b.date, "data": list(b.data_classes), "flags": sorted(b.flags)}
                for b in sorted(breaches, key=lambda b: b.date, reverse=True)
            ],
            "exposed_data": exposed,
            **({"source": source.attribution} if source and source.attribution else {}),
        },
    )
