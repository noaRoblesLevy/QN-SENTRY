"""Attack Surface: open ports and service versions of the approved addresses (issue #5)."""

import json

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.attack_surface import AttackSurfaceModule, classify, port_findings, ports, subdomains
from qnsentry.modules.attack_surface.ports import Service, parse_naabu_output, parse_nmap_xml
from qnsentry.modules.attack_surface.subdomains import Host
from qnsentry.modules.base import ScanContext

DOMAIN = "badsecurityinc.be"

# Captured from the worker image: nmap -sT -sV -Pn -n -p 5432,22 -oX - against a PostgreSQL
# container (the address replaced by a documentation address)
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -n -p 5432,22 -oX - 192.0.2.10" version="7.95">
<host starttime="1791484240" endtime="1791484246"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="tcp" portid="22"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="5432"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="postgresql" product="PostgreSQL DB" version="9.6.0 or later" method="probed" conf="10"><cpe>cpe:/a:postgresql:postgresql</cpe></service></port>
</ports>
</host>
</nmaprun>
"""

LIVE_HOSTS = [
    {"name": "badsecurityinc.be", "ips": ["76.76.21.21"], "cdn": None},
    {"name": "www.badsecurityinc.be", "ips": ["76.76.21.21"], "cdn": None},
    {"name": "dev.badsecurityinc.be", "ips": ["192.0.2.10"], "cdn": None},
]


# ---------- Parsing the tools' output ----------


def test_naabu_output_gives_each_open_port_once_sorted():
    # naabu reported 5432 twice in the worker image
    output = "\n".join(
        [
            json.dumps({"ip": "192.0.2.10", "port": 5432, "protocol": "tcp"}),
            json.dumps({"ip": "192.0.2.10", "port": 22, "protocol": "tcp"}),
            json.dumps({"ip": "192.0.2.10", "port": 5432, "protocol": "tcp"}),
            json.dumps({"ip": "2001:db8::10", "port": 443}),
            "not json",
            "",
        ]
    )

    assert parse_naabu_output(output) == {"192.0.2.10": [22, 5432], "2001:db8::10": [443]}


def test_nmap_xml_gives_the_open_ports_with_service_product_and_version():
    assert parse_nmap_xml(NMAP_XML) == [
        Service(
            ip="192.0.2.10", port=5432, protocol="tcp", service="postgresql",
            product="PostgreSQL DB", version="9.6.0 or later",
        )
    ]


def test_unreadable_nmap_output_is_an_error():
    with pytest.raises(RuntimeError, match="nmap gave no readable output"):
        parse_nmap_xml("Starting Nmap 7.95")


# ---------- The commands ----------


def capture(monkeypatch, stdout=""):
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs.get("input")))
        return ports.subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(ports.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(ports.subprocess, "run", run)
    return commands


def test_naabu_does_a_connect_scan_of_the_top_ports_of_the_given_addresses_only(monkeypatch):
    commands = capture(monkeypatch)

    ports.open_ports(["192.0.2.10", "2001:db8::10"])

    [(command, stdin)] = commands
    assert command[command.index("-s") + 1] == "c"  # no raw packets, no root
    assert command[command.index("-top-ports") + 1] == ports.TOP_PORTS
    assert "-exclude-cdn" in command and "-duc" in command and "-rate" in command
    # Only the addresses: naabu never resolves host names itself
    assert stdin == "192.0.2.10\n2001:db8::10"
    assert not {"-host", "-l", "-list", "-p-"} & set(command)


def test_nmap_identifies_only_the_open_ports_with_a_connect_scan(monkeypatch):
    commands = capture(monkeypatch, stdout=NMAP_XML)

    ports.identify("192.0.2.10", [22, 5432])
    ports.identify("2001:db8::10", [443])

    [(ipv4, _), (ipv6, _)] = commands
    assert "-sT" in ipv4 and "-sV" in ipv4 and "-sS" not in ipv4
    assert ipv4[ipv4.index("-p") + 1] == "22,5432"
    assert ipv4[-1] == "192.0.2.10" and "-6" not in ipv4
    assert ipv6[-2:] == ["-6", "2001:db8::10"]


@pytest.mark.parametrize("tool", ["naabu", "nmap"])
def test_missing_tool_is_a_clear_error(monkeypatch, tool):
    monkeypatch.setattr(ports.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match=f"{tool} is not installed"):
        ports.open_ports(["192.0.2.10"]) if tool == "naabu" else ports.identify("192.0.2.10", [22])


# ---------- Severity ----------


@pytest.mark.parametrize(
    ("service", "severity", "what"),
    [
        (Service("192.0.2.10", 5432, service="postgresql"), Severity.HIGH, "PostgreSQL database"),
        # nmap's name comes first: a database on another port is still a database
        (Service("192.0.2.10", 15432, service="postgresql"), Severity.HIGH, "PostgreSQL database"),
        # Not identified: the usual port decides
        (Service("192.0.2.10", 3389), Severity.HIGH, "Remote Desktop (RDP)"),
        (Service("192.0.2.10", 23, service="telnet"), Severity.HIGH, "Telnet"),
        (Service("192.0.2.10", 445, service="microsoft-ds"), Severity.HIGH, "SMB file sharing"),
        (Service("192.0.2.10", 22, service="ssh"), Severity.MEDIUM, "SSH"),
        (Service("192.0.2.10", 21), Severity.MEDIUM, "FTP"),
        (Service("192.0.2.10", 443, service="http"), Severity.INFO, "Web server"),
        (Service("192.0.2.10", 80), Severity.INFO, "Web server"),
        # A web server on a database port is a web server
        (Service("192.0.2.10", 3306, service="http"), Severity.INFO, "Web server"),
        (Service("192.0.2.10", 9999, service="abyss"), Severity.LOW, "Service abyss"),
        (Service("192.0.2.10", 9999), Severity.LOW, "Unknown service"),
    ],
)
def test_risky_services_get_a_higher_severity_than_web_ports(service, severity, what):
    assert classify(service)[0] == severity
    assert classify(service)[2] == what


# ---------- Only approved addresses are scanned (#81) ----------


def fake_scan(monkeypatch, open_ports=None, services=None, naabu_error=None, nmap_error=None):
    """open_ports: {ip: [ports]}; services: [Service]. Returns the addresses given to naabu."""
    scanned = []

    def fake_open_ports(ips):
        scanned.extend(ips)
        if naabu_error:
            raise naabu_error
        return {ip: found for ip, found in (open_ports or {}).items() if ip in ips}

    def fake_identify(ip, numbers):
        if nmap_error:
            raise nmap_error
        return [s for s in services or [] if s.ip == ip and s.port in numbers]

    monkeypatch.setattr(ports, "open_ports", fake_open_ports)
    monkeypatch.setattr(ports, "identify", fake_identify)
    return scanned


def test_nothing_is_port_scanned_without_an_approval(monkeypatch):
    scanned = fake_scan(monkeypatch, open_ports={"192.0.2.10": [22]})
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS)

    findings = port_findings(context)

    assert findings == [] and scanned == []
    assert context.warnings == ["2 address(es) were not port-scanned because they were not confirmed"]


def test_only_the_approved_address_is_scanned(monkeypatch):
    # The test environment: the VM approved, Vercel not
    scanned = fake_scan(
        monkeypatch,
        open_ports={"192.0.2.10": [22, 5432]},
        services=[
            Service("192.0.2.10", 22, service="ssh", product="OpenSSH", version="9.6p1"),
            Service("192.0.2.10", 5432, service="postgresql", product="PostgreSQL DB", version="9.6.0 or later"),
        ],
    )
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS, port_scan_ips=["192.0.2.10"])

    findings = port_findings(context)

    assert scanned == ["192.0.2.10"]
    assert [(f.type, f.asset, f.severity) for f in findings] == [
        ("open_port", "192.0.2.10:22", Severity.MEDIUM),
        ("open_port", "192.0.2.10:5432", Severity.HIGH),
    ]
    assert findings[1].title == "PostgreSQL database on 192.0.2.10:5432 (PostgreSQL DB 9.6.0 or later)"
    assert findings[1].details == {
        "ip": "192.0.2.10", "port": 5432, "protocol": "tcp", "hosts": ["dev.badsecurityinc.be"],
        "service": "postgresql", "product": "PostgreSQL DB", "version": "9.6.0 or later",
    }
    assert context.warnings == ["1 address(es) were not port-scanned because they were not confirmed"]


def test_a_cdn_address_is_never_scanned_also_when_approved(monkeypatch):
    scanned = fake_scan(monkeypatch, open_ports={"104.16.132.229": [80, 443]})
    live_hosts = [{"name": "www.badsecurityinc.be", "ips": ["104.16.132.229"], "cdn": "cloudflare"}]
    context = ScanContext(domain=DOMAIN, live_hosts=live_hosts, port_scan_ips=["104.16.132.229"])

    findings = port_findings(context)

    assert findings == [] and scanned == []
    assert context.warnings == [
        "1 address(es) of a CDN (cloudflare) were not port-scanned: they are shared with other websites"
    ]


def test_a_failing_port_scan_is_a_warning(monkeypatch):
    fake_scan(monkeypatch, naabu_error=RuntimeError("naabu did not finish within 600 s"))
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS, port_scan_ips=["192.0.2.10"])

    assert port_findings(context) == []
    assert "Open ports could not be checked: naabu did not finish within 600 s" in context.warnings


def test_open_ports_are_still_reported_when_nmap_fails(monkeypatch):
    fake_scan(monkeypatch, open_ports={"192.0.2.10": [3389]}, nmap_error=RuntimeError("nmap failed"))
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS, port_scan_ips=["192.0.2.10"])

    [finding] = port_findings(context)

    assert (finding.asset, finding.severity) == ("192.0.2.10:3389", Severity.HIGH)
    assert finding.title == "Remote Desktop (RDP) on 192.0.2.10:3389"
    assert "The services of 1 address(es) could not be identified, only their open ports" in context.warnings


def test_ipv6_addresses_are_written_with_brackets(monkeypatch):
    fake_scan(monkeypatch, open_ports={"2001:db8::10": [443]}, services=[Service("2001:db8::10", 443, service="http")])
    live_hosts = [{"name": "dev.badsecurityinc.be", "ips": ["2001:db8::10"], "cdn": None}]
    context = ScanContext(domain=DOMAIN, live_hosts=live_hosts, port_scan_ips=["2001:db8::10"])

    [finding] = port_findings(context)

    assert finding.asset == "[2001:db8::10]:443"


def test_the_module_runs_the_port_scan_on_its_own_live_hosts(monkeypatch):
    # The port scan uses the hosts the module just found, not those of an earlier scan
    def fake_discover(domain, warn):
        return [Host("badsecurityinc.be", ["76.76.21.21"]), Host("dev.badsecurityinc.be", ["192.0.2.10"])]

    monkeypatch.setattr("qnsentry.modules.attack_surface.discover", fake_discover)
    fake_scan(monkeypatch, open_ports={"192.0.2.10": [23]}, services=[Service("192.0.2.10", 23, service="telnet")])
    context = ScanContext(domain=DOMAIN, port_scan_ips=["192.0.2.10"])

    findings = AttackSurfaceModule().run(context)

    assert [(f.type, f.severity) for f in findings] == [("subdomain", Severity.INFO), ("open_port", Severity.HIGH)]
    assert context.warnings == [
        "1 address(es) were not port-scanned because they were not confirmed",
        "Web services are not checked yet in this version of QN-Sentry",
    ]


def test_dnsx_reports_the_cdn_of_a_host():
    # dnsx -cdn output for cloudflare.com, captured from the worker image
    line = json.dumps({"host": "www.badsecurityinc.be", "a": ["104.16.132.229"], "cdn": True, "cdn-name": "cloudflare"})

    assert subdomains.parse_dnsx_output(line)["www.badsecurityinc.be"].cdn == "cloudflare"
