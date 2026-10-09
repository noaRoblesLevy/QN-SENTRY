"""Open ports and service versions of the addresses the user approved (issue #5).

1. Only ScanContext.port_scan_targets() is scanned: addresses the user approved (#81), found
   again for a live host in this scan and not of a known CDN. The TXT record of #48 proves
   control of the domain, not of the servers behind it (legal framework 5.2).
2. naabu finds the open ports among the most common ones with a TCP connect scan: no raw
   packets, so the worker runs as non-root. -exclude-cdn stays on as a safety net.
3. nmap -sT -sV identifies the service, product and version on only those open ports.
"""

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass

# Keep the scan small and gentle: the most common ports, a limited packet rate
TOP_PORTS = "1000"
RATE = 300
NAABU_TIMEOUT_SECONDS = 600
NMAP_TIMEOUT_SECONDS = 600
# For all addresses together: no new nmap run starts after this, so naabu and nmap stay well
# under SCAN_TIMEOUT_MINUTES (120) also with many approved addresses
NMAP_BUDGET_SECONDS = 1200


@dataclass
class Service:
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""  # nmap's name for it, e.g. "postgresql"
    product: str = ""  # e.g. "PostgreSQL DB"
    version: str = ""  # e.g. "9.6.0 or later"


def open_ports(ips: list[str]) -> dict[str, list[int]]:
    """{ip: [open ports]} from naabu. Raises RuntimeError when naabu cannot run."""
    if shutil.which("naabu") is None:
        raise RuntimeError("naabu is not installed in the worker image")
    command = [
        "naabu",
        "-s", "c",  # TCP connect scan: no raw packets, no root
        "-top-ports", TOP_PORTS,
        "-rate", str(RATE),
        "-iv", "4,6",
        # A safety net only: it still scans ports 80 and 443 of a CDN address, so
        # port_scan_targets() already leaves those addresses out
        "-exclude-cdn",
        "-json", "-silent", "-nc",
        "-duc",
    ]
    try:
        result = subprocess.run(
            command, input="\n".join(ips), capture_output=True, text=True, timeout=NAABU_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"naabu did not finish within {NAABU_TIMEOUT_SECONDS} s") from error
    if result.returncode != 0:
        stderr = result.stderr.strip().splitlines()
        raise RuntimeError(f"naabu failed: {stderr[-1] if stderr else f'exit code {result.returncode}'}")
    return parse_naabu_output(result.stdout)


def parse_naabu_output(output: str) -> dict[str, list[int]]:
    """{ip: [ports]}, sorted, each port once: naabu can report the same port twice."""
    found: dict[str, set[int]] = {}
    for line in output.split("\n"):
        try:
            entry = json.loads(line)
            ip, port = str(entry["ip"]), int(entry["port"])
        except (ValueError, KeyError, TypeError):
            continue
        found.setdefault(ip, set()).add(port)
    return {ip: sorted(ports) for ip, ports in found.items()}


def identify(ip: str, ports: list[int]) -> list[Service]:
    """The services on the open ports of one address. Raises RuntimeError when nmap fails."""
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed in the worker image")
    command = [
        "nmap",
        "-sT", "-sV",  # TCP connect, as non-root
        "-Pn", "-n",  # the address is known to be up, and no reverse DNS lookups
        "-p", ",".join(str(port) for port in ports),
        "-oX", "-",
        *(["-6"] if ":" in ip else []),
        ip,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=NMAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"nmap did not finish within {NMAP_TIMEOUT_SECONDS} s") from error
    if result.returncode != 0:
        stderr = result.stderr.strip().splitlines()
        raise RuntimeError(f"nmap failed: {stderr[-1] if stderr else f'exit code {result.returncode}'}")
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(output: str) -> list[Service]:
    """The open ports in nmap's XML output, with the service nmap identified on them."""
    try:
        root = ET.fromstring(output)
    except ET.ParseError as error:
        raise RuntimeError(f"nmap gave no readable output: {error}") from error
    services = []
    for host in root.iter("host"):
        address = host.find("address")
        if address is None:
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append(
                Service(
                    ip=address.get("addr", ""),
                    port=int(port.get("portid", 0)),
                    protocol=port.get("protocol", "tcp"),
                    service=service.get("name", "") if service is not None else "",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                )
            )
    return services
