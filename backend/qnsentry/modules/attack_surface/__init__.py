"""Attack Surface Mapping: what of the organisation is reachable from the internet.

1. Subdomains from passive sources, resolved to IP addresses (#4, subdomains.py)
2. Open ports and service versions of the addresses the user approved (#5, ports.py)
3. Web services and technologies (#6)

The live hosts go into the scan context, so the port and web checks scan exactly those.
"""

from dataclasses import asdict

from qnsentry.db.models import Severity
from qnsentry.modules.attack_surface import ports
from qnsentry.modules.attack_surface.ports import Service
from qnsentry.modules.attack_surface.subdomains import Host, discover
from qnsentry.modules.base import Finding, Module, ScanContext

MODULE = "attack_surface"

# Services that should only be reachable from the internal network or through a VPN, by
# nmap's service name and by their usual port (for when nmap could not identify it)
EXPOSED_SERVICES = {
    "telnet": "Telnet",
    "microsoft-ds": "SMB file sharing",
    "netbios-ssn": "SMB file sharing",
    "ms-wbt-server": "Remote Desktop (RDP)",
    "vnc": "VNC remote desktop",
    "ms-sql-s": "Microsoft SQL Server",
    "oracle-tns": "Oracle database",
    "mysql": "MySQL database",
    "postgresql": "PostgreSQL database",
    "redis": "Redis database",
    "mongodb": "MongoDB database",
    "memcached": "Memcached",
}
EXPOSED_PORTS = {
    23: "Telnet",
    139: "SMB file sharing",
    445: "SMB file sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle database",
    2375: "Docker API",
    3306: "MySQL database",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL database",
    5900: "VNC remote desktop",
    6379: "Redis database",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB database",
}
# Remote login, file transfer and mail: often needed, but a target for password guessing
LOGIN_SERVICES = {"ftp": "FTP", "ssh": "SSH", "smtp": "SMTP mail", "pop3": "POP3 mail", "imap": "IMAP mail"}
LOGIN_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP mail",
    110: "POP3 mail",
    143: "IMAP mail",
    465: "SMTP mail",
    587: "SMTP mail",
    993: "IMAP mail",
    995: "POP3 mail",
}
WEB_PORTS = {80, 443, 8080, 8443}


class AttackSurfaceModule(Module):
    name = MODULE

    def run(self, context: ScanContext) -> list[Finding]:
        hosts = discover(context.domain, warn=context.warn)
        context.live_hosts = [{"name": host.name, "ips": list(host.ips), "cdn": host.cdn} for host in hosts]
        # The domain itself is the scanned domain, not a discovered subdomain
        findings = [to_finding(host) for host in hosts if host.name != context.domain]
        findings += port_findings(context)
        # Until #6 exists, the report and the risk score must not present this module as
        # complete (data contract 10.3.1)
        context.warn("Web services are not checked yet in this version of QN-Sentry")
        return findings


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


# ---------- Open ports (#5) ----------


def port_findings(context: ScanContext) -> list[Finding]:
    """Open ports of ScanContext.port_scan_targets() only. The other addresses are counted in
    a warning, so the report and the risk score do not present them as checked."""
    found = {ip for host in context.live_hosts for ip in host["ips"]}
    cdn = {ip for host in context.live_hosts if host.get("cdn") for ip in host["ips"]}
    not_confirmed = found - cdn - set(context.port_scan_ips)
    if cdn:
        names = sorted({host["cdn"] for host in context.live_hosts if host.get("cdn")})
        context.warn(
            f"{len(cdn)} address(es) of a CDN ({', '.join(names)}) were not port-scanned: "
            "they are shared with other websites"
        )
    if not_confirmed:
        context.warn(f"{len(not_confirmed)} address(es) were not port-scanned because they were not confirmed")

    targets = context.port_scan_targets()
    if not targets:
        return []
    try:
        open_ports = ports.open_ports(list(targets))
    except RuntimeError as error:
        context.warn(f"Open ports could not be checked: {error}")
        return []

    findings = []
    unidentified = 0
    for ip, numbers in open_ports.items():
        if ip not in targets:  # only report addresses that were allowed to be scanned
            continue
        try:
            services = {service.port: service for service in ports.identify(ip, numbers)}
        except RuntimeError:
            unidentified += 1
            services = {}
        for number in numbers:
            # A port nmap did not identify is still reported: naabu found it open
            service = services.get(number) or Service(ip=ip, port=number)
            findings.append(port_finding(service, targets[ip]))
    if unidentified:
        context.warn(f"The services of {unidentified} address(es) could not be identified, only their open ports")
    return findings


def classify(service: Service) -> tuple[Severity, str, str]:
    """(severity, kind, what it is). nmap's name for the service comes first: a database on
    another port is still a database."""
    if service.service in EXPOSED_SERVICES:
        return Severity.HIGH, "exposed", EXPOSED_SERVICES[service.service]
    if service.service in LOGIN_SERVICES:
        return Severity.MEDIUM, "login", LOGIN_SERVICES[service.service]
    if service.service.startswith("http") or (not service.service and service.port in WEB_PORTS):
        return Severity.INFO, "web", "Web server"
    if service.port in EXPOSED_PORTS:
        return Severity.HIGH, "exposed", EXPOSED_PORTS[service.port]
    if service.port in LOGIN_PORTS:
        return Severity.MEDIUM, "login", LOGIN_PORTS[service.port]
    return Severity.LOW, "other", f"Service {service.service}" if service.service else "Unknown service"


def port_finding(service: Service, hosts: list[str]) -> Finding:
    severity, kind, what = classify(service)
    software = " ".join(part for part in [service.product, service.version] if part)
    where = f"port {service.port} of {service.ip} ({', '.join(hosts)})"
    version_note = (
        f" The server also tells which software it runs ({software}), so an attacker knows which "
        "known vulnerabilities to try."
        if service.version
        else ""
    )
    descriptions = {
        "exposed": (
            f"{what} is reachable from the internet on {where}. This kind of service belongs on "
            "the internal network or behind a VPN: attackers scan the whole internet for it and "
            f"try default or stolen passwords and known vulnerabilities.{version_note} Close the "
            "port in the firewall, or allow only the addresses that need it."
        ),
        "login": (
            f"{what} is reachable from the internet on {where}. It lets people log in or exchange "
            "files or mail, so attackers try passwords on it and look for known vulnerabilities."
            f"{version_note} Check that it is needed, keep it up to date and protect it with strong "
            "authentication, such as keys instead of passwords for SSH."
        ),
        "web": (
            f"A web server answers on {where}. This is expected for a website, but every web "
            f"server is software that can have vulnerabilities.{version_note} Keep it up to date "
            "and check that only the intended websites run on it."
        ),
        "other": (
            f"An open port was found on {where} ({what.lower()}). Every open port is a possible way "
            "in, and a service nobody knows about is rarely kept up to date."
            f"{version_note} Check that the service is needed and close the port in the firewall "
            "otherwise."
        ),
    }
    host = f"[{service.ip}]" if ":" in service.ip else service.ip
    return Finding(
        module=MODULE,
        type="open_port",
        title=f"{what} on {host}:{service.port}" + (f" ({software})" if software else ""),
        description=descriptions[kind],
        severity=severity,
        asset=f"{host}:{service.port}",
        details={
            "ip": service.ip,
            "port": service.port,
            "protocol": service.protocol,
            "hosts": hosts,
            "service": service.service,
            "product": service.product,
            "version": service.version,
        },
    )
