"""Published email addresses and the naming convention they follow (issue #8).

1. The HTML pages the crawl found are fetched again (katana only reports their URLs) and
   the addresses of the client's domain are taken from their mailto: links and text.
2. The author names from the documents are matched against those addresses to find the
   convention (data contract 10.4.2) and how a last name of several words is written
   (10.4.3). The Breach module (#12) then derives the addresses that were never published.
"""

import html
import logging
import re
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.metadata.crawler import is_document
from qnsentry.modules.metadata.documents import USER_AGENT, OffHostRedirect, SameHostRedirects
from qnsentry.modules.names import CONVENTIONS, JOINED, SEPARATED, local_part, separator, split_name

log = logging.getLogger(__name__)

MODULE = "metadata"
# Keep the extra requests small and polite, like the crawl
MAX_PAGES = 30
MAX_PAGE_BYTES = 2 * 1024 * 1024
SECONDS_BETWEEN_PAGES = 0.1  # 10 requests per second, as the crawl
# A convention needs this many names that match a published address: one match can be chance
MIN_MATCHES = 2
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NOT_PAGES = {
    ".css", ".js", ".mjs", ".json", ".xml", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".zip", ".gz",
}


@dataclass
class Convention:
    convention: str
    # JOINED or SEPARATED, or None when no published address has a last name of several words
    last_name_style: str | None
    # (name, address) pairs that showed the convention
    evidence: list[tuple[str, str]] = field(default_factory=list)


# ---------- Collecting addresses ----------


def page_urls(urls: list[str], allowed_hosts: set[str]) -> list[str]:
    """The URLs of the crawl that can be web pages, each path once (like document_urls)."""
    pages = []
    seen_paths = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed_hosts:
            continue
        if is_document(url) or PurePosixPath(unquote(parsed.path)).suffix.lower() in NOT_PAGES:
            continue
        path = (parsed.path.rstrip("/"), parsed.query)
        if path not in seen_paths:
            seen_paths.add(path)
            pages.append(url)
    return pages


def fetch_page(url: str, allowed_hosts: set[str]) -> str | None:
    """The HTML of `url`, or None when it is not an HTML page. Raises OSError when it fails.

    Redirects are only followed within the allowed hosts (#66).
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(SameHostRedirects(allowed_hosts))
    with opener.open(request, timeout=30) as response:
        if "html" not in (response.headers.get_content_type() or ""):
            return None
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read(MAX_PAGE_BYTES).decode(charset, errors="replace")


def extract_emails(page: str, domain: str) -> list[str]:
    """The addresses of `domain` (or its subdomains) in a page, lowercase, in order, each once."""
    text = unquote(html.unescape(page))
    found = []
    for match in EMAIL.findall(text):
        address = match.lower().strip(".")
        address_domain = address.rsplit("@", 1)[1]
        if (address_domain == domain or address_domain.endswith(f".{domain}")) and address not in found:
            found.append(address)
    return found


def collect_emails(
    urls: list[str], allowed_hosts: set[str], domain: str, warn: Callable[[str], None] = lambda message: None
) -> dict[str, list[str]]:
    """The addresses of `domain` on the crawled pages, with the pages they appear on."""
    pages = page_urls(urls, allowed_hosts)
    emails: dict[str, list[str]] = {}
    failed = 0
    for index, url in enumerate(pages[:MAX_PAGES]):
        if index:
            time.sleep(SECONDS_BETWEEN_PAGES)
        try:
            page = fetch_page(url, allowed_hosts)
        except OffHostRedirect:
            continue  # a page that leads to another website is not the client's
        except (OSError, ValueError) as error:
            log.warning("Could not load %s: %s", url, error)
            failed += 1
            continue
        for address in extract_emails(page or "", domain):
            emails.setdefault(address, []).append(url)

    checked = min(len(pages), MAX_PAGES)
    if failed:
        warn(f"{failed} of {checked} page(s) could not be loaded, so email addresses on them may have been missed")
    if len(pages) > MAX_PAGES:
        warn(f"Only the first {MAX_PAGES} of {len(pages)} pages were checked for email addresses")
    return emails


# ---------- Detecting the convention ----------


def detect_convention(names: list[str], emails: list[str], domain: str) -> Convention | None:
    """The convention that most names match to a published address, if at least MIN_MATCHES do.

    For a name with a last name of several words both styles are tried, which also tells how
    the company writes them (contract 10.4.3). On a tie the more common convention wins
    (the order of CONVENTIONS).
    """
    local_parts = {address.rsplit("@", 1)[0]: address for address in emails if address.endswith(f"@{domain}")}
    best: Convention | None = None
    for convention in CONVENTIONS:
        evidence: list[tuple[str, str]] = []
        styles: list[str] = []
        for name in names:
            parts = split_name(name)
            if parts is None:
                continue
            for style in (JOINED, SEPARATED):
                candidate = local_part(name, convention, style)
                if candidate in local_parts:
                    evidence.append((name, local_parts[candidate]))
                    # Only a last name of several words, with a separator, shows the style
                    if len(parts[1]) > 1 and separator(convention):
                        styles.append(style)
                    break
        if len(evidence) >= MIN_MATCHES and (best is None or len(evidence) > len(best.evidence)):
            style = max(set(styles), key=styles.count) if styles else None
            best = Convention(convention, style, evidence)
    return best


# ---------- Findings ----------


def to_address_finding(emails: dict[str, list[str]], domain: str) -> Finding:
    count = len(emails)
    return Finding(
        module=MODULE,
        type="email_address",
        title=f"{count} email address{'es' if count != 1 else ''} of {domain} "
        f"{'are' if count != 1 else 'is'} published on the website",
        description=(
            "The website publishes these business email addresses. That is normal for contact "
            "addresses, but every published address can receive phishing emails, and QN-Sentry "
            "checks them against known data breaches. Where possible, publish a general address "
            "(such as info@) or a contact form instead of personal addresses."
        ),
        severity=Severity.INFO,
        asset=domain,
        details={"addresses": [{"address": address, "pages": pages} for address, pages in emails.items()]},
    )


def to_convention_finding(convention: Convention, domain: str, names_checked: int) -> Finding:
    name, address = convention.evidence[0]
    return Finding(
        module=MODULE,
        type="email_convention",
        title=f"Email addresses of {domain} follow the pattern {convention.convention}",
        description=(
            f"The published addresses show how addresses are built (for example {name}: {address}). "
            "With a name from a document, a social network or the website, an attacker can guess "
            "the address of any employee, also of people whose address is not published, and send "
            "them targeted phishing. A predictable pattern is common and hard to change: make "
            "employees aware of phishing and protect their accounts with multi-factor authentication."
        ),
        severity=Severity.LOW,
        asset=domain,
        details={
            "convention": convention.convention,
            "last_name_style": convention.last_name_style,
            "evidence": [{"name": n, "address": a} for n, a in convention.evidence],
            "names_checked": names_checked,
        },
    )
