"""Employee Breach Exposure: business email addresses that appear in known data breaches.

The addresses come from the scan context, filled by the Metadata module (#8): addresses
published on the website. Addresses derived from author names and the email convention
are added in #12. Until the Metadata module exists, the context has no addresses and this
module returns no findings.
"""

from collections.abc import Callable

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.breach.sources import Breach, BreachSource, get_breach_source

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


class BreachModule(Module):
    name = MODULE

    def __init__(self, source_factory: Callable[[], BreachSource] = get_breach_source) -> None:
        # The source is created when a scan runs, so configuration changes need no restart
        self.source_factory = source_factory

    def run(self, context: ScanContext) -> list[Finding]:
        source = self.source_factory()
        findings = []
        for email in sorted({e.strip().lower() for e in context.emails if e.strip()}):
            breaches = source.lookup(email)
            if breaches:
                findings.append(to_finding(email, breaches, origin="found publicly"))
        return findings


def to_finding(email: str, breaches: list[Breach], origin: str) -> Finding:
    exposed = sorted({data for breach in breaches for data in breach.data_classes})
    sensitive = sorted(set(exposed) & SENSITIVE_DATA)
    count = len(breaches)
    title = f"{email} appears in {count} data breach{'es' if count != 1 else ''}"

    if sensitive:
        severity = Severity.HIGH
        description = (
            f"This business email address appears in known data breaches that exposed "
            f"{', '.join(s.lower() for s in sensitive)}. If the employee reuses that password for "
            "company accounts, an attacker can try it on the company's email, VPN or other "
            "systems (credential stuffing). Ask the employee to change the password everywhere it "
            "was used and turn on multi-factor authentication."
        )
    else:
        severity = Severity.MEDIUM
        description = (
            "This business email address appears in known data breaches. No passwords were "
            "exposed, but attackers know the address is real and can use the leaked details to "
            "make phishing emails more convincing."
        )

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
                {"name": b.name, "date": b.date, "data": list(b.data_classes)}
                for b in sorted(breaches, key=lambda b: b.date, reverse=True)
            ],
            "exposed_data": exposed,
        },
    )
