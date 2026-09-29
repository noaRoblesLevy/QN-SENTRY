"""Find the pages and public documents of the client's website with katana (issue #7)."""

import json
import logging
import shutil
import subprocess
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

log = logging.getLogger(__name__)

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"}

# Keep the crawl small and polite: it runs against a real website
MAX_DEPTH = 3
CRAWL_SECONDS = 120
REQUESTS_PER_SECOND = 10


def start_urls(domain: str) -> list[str]:
    return [f"https://{domain}", f"https://www.{domain}"]


def crawl(urls: list[str]) -> list[str]:
    """All URLs katana finds from `urls`, staying on the exact host of each start URL."""
    if shutil.which("katana") is None:
        raise RuntimeError("katana is not installed in the worker image")

    command = [
        "katana",
        "-u", ",".join(urls),
        "-field-scope", "fqdn",  # never leave the host of the start URL
        "-depth", str(MAX_DEPTH),
        "-crawl-duration", f"{CRAWL_SECONDS}s",
        "-rate-limit", str(REQUESTS_PER_SECOND),
        # katana hides .pdf, .xlsx, ... by default; those are exactly the files we need
        "-no-default-ext-filter",
        # Only the URLs are needed, not the (binary) contents of every response
        "-jsonl",
        "-omit-body",
        "-omit-raw",
        "-silent",
        "-no-color",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=CRAWL_SECONDS + 60)
    except subprocess.TimeoutExpired:
        log.warning("katana did not stop after %s s", CRAWL_SECONDS + 60)
        return []
    return parse_katana_output(result.stdout)


def parse_katana_output(output: str) -> list[str]:
    """The endpoints from katana's JSON lines, in the order found, without duplicates."""
    found: list[str] = []
    # split("\n"), not splitlines(): splitlines() also breaks on characters like U+0085
    # that can appear inside a JSON string, which would cut a JSON line in pieces
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            endpoint = json.loads(line).get("request", {}).get("endpoint")
        except (ValueError, AttributeError):
            endpoint = line if line.startswith(("http://", "https://")) else None
        if endpoint and endpoint not in found:
            found.append(endpoint)
    return found


def document_urls(urls: list[str], allowed_hosts: set[str]) -> list[str]:
    """The URLs that point to a document on one of the allowed hosts."""
    documents = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed_hosts:
            continue
        if PurePosixPath(unquote(parsed.path)).suffix.lower() in DOCUMENT_EXTENSIONS:
            documents.append(url)
    return documents
