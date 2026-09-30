"""Find the pages and public documents of the client's website with katana (issue #7)."""

import json
import shutil
import subprocess
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

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
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"katana did not finish within {CRAWL_SECONDS + 60} s") from error

    found, errors = parse_katana_output(result.stdout)
    if not found:
        # Not even the start page answered (site offline, DNS or TLS error). Reporting
        # "0 findings" would look like a clean site, so the module fails instead
        # (data contract 10.3.1: total failure). katana still exits with 0 then.
        stderr = result.stderr.strip().splitlines()
        reason = errors[0] if errors else stderr[-1] if stderr else f"exit code {result.returncode}"
        raise RuntimeError(f"The website {', '.join(urls)} could not be crawled: {reason}")
    return found


def parse_katana_output(output: str) -> tuple[list[str], list[str]]:
    """The endpoints katana reached, in the order found and without duplicates, and its errors.

    katana also writes a JSON line for a request that failed, with an "error" field
    and no response; those endpoints were never reached, so they are not returned.
    """
    found: list[str] = []
    errors: list[str] = []
    # split("\n"), not splitlines(): splitlines() also breaks on characters like U+0085
    # that can appear inside a JSON string, which would cut a JSON line in pieces
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            endpoint = entry.get("request", {}).get("endpoint")
            error = entry.get("error")
        except (ValueError, AttributeError):
            endpoint = line if line.startswith(("http://", "https://")) else None
            error = None
        if error:
            errors.append(f"{endpoint}: {error}" if endpoint else str(error))
        elif endpoint and endpoint not in found:
            found.append(endpoint)
    return found, errors


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
