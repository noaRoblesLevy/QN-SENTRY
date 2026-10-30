"""Web services and technologies of the live hosts (issue #6).

httpx (ProjectDiscovery, not the Python package) visits the start page of every live host
once, on the default web ports, like a browser would. It only sends normal requests: no paths
are guessed and nothing is submitted, so a login page is found on the start page or not at all.

Redirects are only followed on the same host: a redirect must never bring the scan to a server
of someone else (#66). The page itself is only read to see if it asks for a password, and is
not stored.
"""

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from qnsentry.modules.attack_surface.subdomains import RESOLVERS

# Keep the scan small and gentle: at most 200 hosts (#4), few requests at a time
RATE_LIMIT = 10
THREADS = 10
TIMEOUT_SECONDS = 10
HTTPX_TIMEOUT_SECONDS = 600

PASSWORD_FIELD = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']?password""", re.IGNORECASE)
# Name and version in a Server header ("nginx/1.18.0") or a technology ("PHP:7.4.3"). The exact
# names only: phpMyAdmin or Apache Struts have version numbers of their own
SOFTWARE = re.compile(r"^(nginx|php|apache)(?: http server)?[:/ ]v?(\d+)\.(\d+)", re.IGNORECASE)
# Oldest branch that still got security fixes in October 2026; older ones get none anymore.
# Only software with a clear support policy, so "outdated" stays a fact and not an opinion
OLDEST_SUPPORTED = {"nginx": (1, 26), "php": (8, 2), "apache": (2, 4)}
# PHP2Shell: unauthenticated remote code execution, exploited since October 2026. The first
# fixed release per branch (php.net, 21/10/2026); older branches got no release. Keep this
# table up to date: a new critical PHP vulnerability needs new numbers here
PHP2SHELL_CVES = ["CVE-2026-109618", "CVE-2026-109619"]
PHP2SHELL_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP_VERSION = re.compile(r"^php[:/ ]v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


@dataclass
class WebService:
    url: str
    host: str
    status: int
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    login_page: bool = False
    outdated: list[str] = field(default_factory=list)  # e.g. ["nginx 1.18", "PHP 7.4"]
    unpatched_php: str = ""  # e.g. "8.4.26": a PHP version below the fix of PHP2SHELL_FIXED


def probe(hosts: list[str]) -> list[WebService]:
    """The web services that answer on `hosts`. Raises RuntimeError when httpx cannot run.

    httpx also exits with 0 and prints nothing when it cannot reach anything, so an empty
    list does not prove that there are no web services: the caller decides.
    """
    if shutil.which("httpx") is None:
        raise RuntimeError("httpx is not installed in the worker image")
    command = [
        "httpx",
        "-json", "-silent", "-nc",
        "-status-code", "-title", "-web-server", "-tech-detect",
        "-include-response",  # the page, only to see if it asks for a password
        "-follow-host-redirects",  # the same host only, never to someone else's server
        "-rate-limit", str(RATE_LIMIT),
        "-threads", str(THREADS),
        "-timeout", str(TIMEOUT_SECONDS),
        "-retries", "1",
        "-r", RESOLVERS,
        "-duc",
    ]
    try:
        result = subprocess.run(
            command, input="\n".join(hosts), capture_output=True, text=True, timeout=HTTPX_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"httpx did not finish within {HTTPX_TIMEOUT_SECONDS} s") from error
    if result.returncode != 0:
        stderr = result.stderr.strip().splitlines()
        raise RuntimeError(f"httpx failed: {stderr[-1] if stderr else f'exit code {result.returncode}'}")
    return parse_httpx_output(result.stdout)


def parse_httpx_output(output: str) -> list[WebService]:
    services = []
    for line in output.split("\n"):
        try:
            entry = json.loads(line)
            url, status = str(entry["url"]), int(entry["status_code"])
        except (ValueError, KeyError, TypeError):
            continue
        if entry.get("failed"):
            continue
        server = entry.get("webserver") or ""
        technologies = entry.get("tech") or []
        services.append(
            WebService(
                url=url,
                host=str(entry.get("input") or entry.get("host") or url),
                status=status,
                title=entry.get("title") or "",
                server=server,
                technologies=technologies,
                login_page=bool(PASSWORD_FIELD.search(entry.get("body") or "")),
                outdated=outdated_software([server, *technologies]),
                unpatched_php=unpatched_php([server, *technologies]),
            )
        )
    return services


def outdated_software(names: list[str]) -> list[str]:
    """The software in `names` on a branch without security fixes, each once."""
    outdated: dict[str, str] = {}
    for name in names:
        match = SOFTWARE.match(name)
        if match is None:
            continue
        product = match.group(1).lower()
        version = (int(match.group(2)), int(match.group(3)))
        if version < OLDEST_SUPPORTED[product]:
            label = "PHP" if product == "php" else product
            outdated.setdefault(product, f"{label} {version[0]}.{version[1]}")
    return list(outdated.values())


def unpatched_php(names: list[str]) -> str:
    """The PHP version in `names` when it is below the fix of PHP2Shell, otherwise "".

    A branch newer than the table counts as fixed. Without a full version nothing can be said.
    """
    for name in names:
        match = PHP_VERSION.match(name)
        if match is None:
            continue
        major, minor, patch = (int(part) for part in match.groups())
        branch = (major, minor)
        if branch < min(PHP2SHELL_FIXED) or patch < PHP2SHELL_FIXED.get(branch, 0):
            return f"{major}.{minor}.{patch}"
    return ""
