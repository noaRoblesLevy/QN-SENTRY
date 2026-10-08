"""Subdomains from passive sources, resolved to their IP addresses (issue #4).

1. subfinder lists the subdomains that public sources know (Certificate Transparency logs,
   passive DNS databases). It never contacts the client's servers and does not guess names
   (no brute force): only names that were seen in public are checked (legal framework 5.2).
2. dnsx resolves them, together with the domain itself and www, through public resolvers
   rather than the container's DNS, which can be slow for names that do not exist.
3. A wildcard record (*.example.be) makes every name resolve. One random name is resolved
   too: when it answers, names that only point to the wildcard's addresses are left out.
"""

import json
import secrets
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

# Keep the passive search and the lookups bounded
SUBFINDER_MINUTES = 2
SOURCE_TIMEOUT_SECONDS = 20
MAX_SUBDOMAINS = 200
RESOLVERS = "1.1.1.1,8.8.8.8,9.9.9.9"


@dataclass
class Host:
    name: str
    ips: list[str] = field(default_factory=list)  # A and AAAA records
    cname: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # passive sources that listed the name


def passive_subdomains(domain: str) -> dict[str, list[str]]:
    """{subdomain: [sources]} from subfinder. Raises RuntimeError when it cannot run."""
    if shutil.which("subfinder") is None:
        raise RuntimeError("subfinder is not installed in the worker image")
    command = [
        "subfinder",
        "-d", domain,
        "-oJ", "-cs",  # JSON lines with the sources of every name
        "-silent", "-nc",
        "-max-time", str(SUBFINDER_MINUTES),
        "-timeout", str(SOURCE_TIMEOUT_SECONDS),
        # No update check at every start: it can hang (#76), and a scan should only contact
        # the sources it needs
        "-duc",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=SUBFINDER_MINUTES * 60 + 60)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"subfinder did not finish within {SUBFINDER_MINUTES * 60 + 60} s") from error
    if result.returncode != 0:
        stderr = result.stderr.strip().splitlines()
        raise RuntimeError(f"subfinder failed: {stderr[-1] if stderr else f'exit code {result.returncode}'}")
    return parse_subfinder_output(result.stdout, domain)


def parse_subfinder_output(output: str, domain: str) -> dict[str, list[str]]:
    """{subdomain: [sources]}, lowercase, only names under `domain`, in the order found."""
    found: dict[str, list[str]] = {}
    for line in output.split("\n"):
        try:
            entry = json.loads(line)
            name = str(entry["host"]).lower().strip().rstrip(".")
        except (ValueError, KeyError, TypeError):
            continue
        if not name.endswith(f".{domain}") or name.startswith("*."):
            continue
        sources = found.setdefault(name, [])
        for source in entry.get("sources") or [entry.get("source")]:
            if source and source not in sources:
                sources.append(source)
    return found


def resolve(names: list[str]) -> dict[str, Host]:
    """The names that resolve, with their addresses and CNAMEs. Raises RuntimeError when dnsx
    cannot run: then nothing was checked."""
    if shutil.which("dnsx") is None:
        raise RuntimeError("dnsx is not installed in the worker image")
    command = [
        "dnsx",
        "-json", "-a", "-aaaa", "-cname",
        "-silent", "-nc",
        "-retry", "2",
        "-r", RESOLVERS,
        "-duc",
    ]
    try:
        result = subprocess.run(command, input="\n".join(names), capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("dnsx did not finish within 180 s") from error
    if result.returncode != 0:
        stderr = result.stderr.strip().splitlines()
        raise RuntimeError(f"dnsx failed: {stderr[-1] if stderr else f'exit code {result.returncode}'}")
    return parse_dnsx_output(result.stdout)


def parse_dnsx_output(output: str) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    for line in output.split("\n"):
        try:
            entry = json.loads(line)
            name = str(entry["host"]).lower().rstrip(".")
        except (ValueError, KeyError, TypeError):
            continue
        if entry.get("status_code", "NOERROR") != "NOERROR":
            continue
        host = hosts.setdefault(name, Host(name))
        for ip in (entry.get("a") or []) + (entry.get("aaaa") or []):
            if ip not in host.ips:
                host.ips.append(ip)
        for target in entry.get("cname") or []:
            target = target.rstrip(".")
            if target not in host.cname:
                host.cname.append(target)
    # A name with only a CNAME to nowhere does not reach a server
    return {name: host for name, host in hosts.items() if host.ips}


def discover(domain: str, warn: Callable[[str], None] = lambda message: None) -> list[Host]:
    """The live hosts of `domain`: the domain itself, www and every subdomain from passive
    sources that resolves. Partial failures are reported to `warn`."""
    try:
        passive = passive_subdomains(domain)
    except RuntimeError as error:
        # The domain itself and www can still be checked
        warn(f"Passive sources could not be searched for subdomains: {error}")
        passive = {}

    names = list(passive)
    if len(names) > MAX_SUBDOMAINS:
        warn(f"Only the first {MAX_SUBDOMAINS} of {len(names)} subdomains from passive sources were checked")
        names = names[:MAX_SUBDOMAINS]
    candidates = list(dict.fromkeys([domain, f"www.{domain}", *names]))
    probe = f"qnsentry-wildcard-{secrets.token_hex(6)}.{domain}"

    resolved = resolve([*candidates, probe])
    wildcard = set(resolved[probe].ips) if probe in resolved else set()

    hosts = []
    behind_wildcard = 0
    for name in candidates:
        host = resolved.get(name)
        if host is None:
            continue
        # With a wildcard every name resolves: only a name that points elsewhere is a real host.
        # The domain itself is always kept.
        if wildcard and name != domain and set(host.ips) <= wildcard:
            behind_wildcard += 1
            continue
        host.sources = passive.get(name, [])
        hosts.append(host)
    if behind_wildcard:
        warn(
            f"{domain} has a wildcard DNS record: {behind_wildcard} name(s) that only resolve "
            "through it were left out"
        )
    return hosts
