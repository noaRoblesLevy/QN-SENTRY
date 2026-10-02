"""Find the pages and public documents of the client's website with katana (issue #7)."""

import json
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"}

# Keep the crawl small and polite: it runs against a real website
MAX_DEPTH = 3
CRAWL_SECONDS = 120
REQUESTS_PER_SECOND = 10
# Lines katana marks as "error" that are not a failed request: the link was simply
# deeper than MAX_DEPTH, which is the crawl's normal limit
NOT_FAILURES = {"max depth reached"}


def start_urls(domain: str) -> list[str]:
    return [f"https://{domain}", f"https://www.{domain}"]


def crawl(urls: list[str], warn: Callable[[str], None] = lambda message: None) -> list[str]:
    """All URLs katana finds from `urls`, staying on the exact host of each start URL.

    Raises when nothing could be reached. When only a part was crawled (a start URL
    that does not answer, failed requests, the time limit), `warn` is told.
    """
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
    started = time.monotonic()
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

    # Only katana's own error for a start URL means it could not be reached. A host missing
    # from the results is no proof: when example.be and www.example.be serve the same site,
    # katana reports each page under one of the two hosts only.
    unreached = [url for url in urls if any(_is_error_for(url, error) for error in errors)]
    for url in unreached:
        warn(f"{url} could not be reached, so it was not crawled")
    failed = [error for error in errors if not any(_is_error_for(url, error) for url in unreached)]
    if failed:
        warn(f"{len(failed)} request(s) failed during the crawl, so some pages may have been missed")
    if time.monotonic() - started >= CRAWL_SECONDS:
        warn(
            f"The crawl stopped at its limit of {CRAWL_SECONDS} s, "
            "so documents deeper in the website may have been missed"
        )
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
        if error in NOT_FAILURES:
            continue
        if error:
            errors.append(f"{endpoint}: {error}" if endpoint else str(error))
        elif endpoint and endpoint not in found:
            found.append(endpoint)
    return found, errors


def _is_error_for(url: str, error: str) -> bool:
    """True when `error` (as returned by parse_katana_output) is about `url` itself."""
    endpoint = error.split(": ", 1)[0]
    return endpoint.rstrip("/") == url.rstrip("/")


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
