"""Attack Surface Mapping: what of the organisation is reachable from the internet.

1. Subdomains from passive sources, resolved to IP addresses (#4, subdomains.py)
2. Open ports and service versions (#5)
3. Web services and technologies (#6)

The live hosts go into the scan context, so the port and web checks scan exactly those.
"""

from dataclasses import asdict

from qnsentry.db.models import Severity
from qnsentry.modules.attack_surface.subdomains import Host, discover
from qnsentry.modules.base import Finding, Module, ScanContext

MODULE = "attack_surface"


class AttackSurfaceModule(Module):
    name = MODULE

    def run(self, context: ScanContext) -> list[Finding]:
        hosts = discover(context.domain, warn=context.warn)
        context.live_hosts = [{"name": host.name, "ips": list(host.ips)} for host in hosts]
        # Until #5 and #6 exist, the report and the risk score must not present this module
        # as complete (data contract 10.3.1)
        context.warn("Open ports and web services are not checked yet in this version of QN-Sentry")
        # The domain itself is the scanned domain, not a discovered subdomain
        return [to_finding(host) for host in hosts if host.name != context.domain]


def to_finding(host: Host) -> Finding:
    addresses = ", ".join(host.ips[:3]) + (f" and {len(host.ips) - 3} more" if len(host.ips) > 3 else "")
    found_in = f" It was found in {', '.join(host.sources)}." if host.sources else ""
    return Finding(
        module=MODULE,
        type="subdomain",
        title=f"Subdomain {host.name} resolves to {addresses}",
        description=(
            f"{host.name} is a public name of the organisation that points to a server on the "
            f"internet.{found_in} Every public host is a possible way in, and attackers list them "
            "first, looking for forgotten test, staging or old systems. Check that every subdomain "
            "is still needed and kept up to date, and remove the DNS records of services that no "
            "longer exist."
        ),
        severity=Severity.INFO,
        asset=host.name,
        details={key: value for key, value in asdict(host).items() if key != "name"},
    )
