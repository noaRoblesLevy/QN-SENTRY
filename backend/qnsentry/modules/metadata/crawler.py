"""Find the pages and public documents of the client's website with katana (issue #7)."""

import json
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlparse

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"}

# Keep the crawl small and polite: it runs against a real website
MAX_DEPTH = 3
CRAWL_SECONDS = 120
REQUESTS_PER_SECOND = 10
# Extra crawl rounds for redirects within the start hosts (e.g. / to /nl/ to /nl/home)
MAX_REDIRECT_ROUNDS = 2
# Seconds katana needs to start, on top of CRAWL_SECONDS of crawling
STARTUP_MARGIN = 5
# Lines katana marks as "error" that are not a failed request: the link was simply
# deeper than MAX_DEPTH, which is the crawl's normal limit
NOT_FAILURES = {"max depth reached"}


def start_urls(domain: str) -> list[str]:
    return [f"https://{domain}", f"https://www.{domain}"]


def crawl(urls: list[str], warn: Callable[[str], None] = lambda message: None) -> list[str]:
    """All URLs katana finds from `urls`, staying on the exact host of each start URL.

    katana never follows a redirect itself (#66): a redirect to another host would send
    that host a request, although only the client's website may be contacted (legal
    framework 5.2). Redirects within the start hosts are followed here instead, by
    crawling their targets in a next round (e.g. a site that sends / to /nl/), at most
    MAX_REDIRECT_ROUNDS times and within the same CRAWL_SECONDS.

    Raises when nothing could be reached. When only a part was crawled (a start URL
    that does not answer, failed requests, the time limit), `warn` is told.
    """
    if shutil.which("katana") is None:
        raise RuntimeError("katana is not installed in the worker image")

    allowed_hosts = {urlparse(url).hostname for url in urls}
    started = time.monotonic()
    deadline = started + CRAWL_SECONDS
    found: list[str] = []
    errors: list[str] = []
    crawled: set[str] = set()
    pending = list(urls)
    first_round = None

    for _ in range(1 + MAX_REDIRECT_ROUNDS):
        if not pending:
            break
        remaining = deadline - time.monotonic()
        if remaining < 1:
            break
        result = _run_katana(pending, remaining)
        first_round = first_round or result
        crawled.update(pending)
        round_found, round_errors = parse_katana_output(result.stdout)
        found += [url for url in round_found if url not in found]
        errors += round_errors
        same_host = [
            (source, target)
            for source, target in redirects(result.stdout)
            if urlparse(target).hostname in allowed_hosts
        ]
        # A document behind a redirect from a page or script (/download?id=3 -> /files/report.pdf)
        # is found through its target. When the source is a document itself (/old.pdf -> /new.pdf),
        # the source is already found and downloading it follows the redirect, so adding the target
        # would download the same file twice.
        found += [
            target
            for source, target in same_host
            if is_document(target) and not is_document(source) and target not in found
        ]
        # Pages behind a redirect (/ -> /nl/) are crawled in the next round
        pending = list(
            dict.fromkeys(
                target
                for _, target in same_host
                if not is_document(target) and target not in crawled and target not in found
            )
        )

    if not found:
        # Not even the start page answered (site offline, DNS or TLS error). Reporting
        # "0 findings" would look like a clean site, so the module fails instead
        # (data contract 10.3.1: total failure). katana still exits with 0 then.
        stderr = first_round.stderr.strip().splitlines()
        reason = errors[0] if errors else stderr[-1] if stderr else f"exit code {first_round.returncode}"
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
    # The margin covers katana's start-up, so a crawl that ends on its own just under the
    # limit is not reported as stopped by it
    if time.monotonic() - started >= CRAWL_SECONDS + STARTUP_MARGIN:
        warn(
            f"The crawl stopped at its limit of {CRAWL_SECONDS} s, "
            "so documents deeper in the website may have been missed"
        )
    return found


def _run_katana(urls: list[str], seconds: float) -> subprocess.CompletedProcess:
    command = [
        "katana",
        "-u", ",".join(urls),
        "-field-scope", "fqdn",  # never leave the host of the start URL
        # Never follow a redirect: one to another host would contact a third party (#66).
        # crawl() follows the redirects that stay on the start hosts itself.
        "-disable-redirects",
        # katana drops responses with the same content as an earlier one. Redirects all have
        # the same (empty) body, so without this only one of them would be reported.
        "-disable-unique-filter",
        "-depth", str(MAX_DEPTH),
        "-crawl-duration", f"{max(1, int(seconds))}s",
        "-rate-limit", str(REQUESTS_PER_SECOND),
        # katana hides .pdf, .xlsx, ... by default; those are exactly the files we need
        "-no-default-ext-filter",
        # Only the URLs and headers are needed, not the (binary) contents of every response
        "-jsonl",
        "-omit-body",
        "-omit-raw",
        "-silent",
        "-no-color",
    ]
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=seconds + 60)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"katana did not finish within {int(seconds) + 60} s") from error


def redirects(output: str) -> list[tuple[str, str]]:
    """The redirects in katana's output as (source, absolute target), in the order found."""
    found = []
    for line in output.split("\n"):
        try:
            entry = json.loads(line)
            endpoint = entry["request"]["endpoint"]
            response = entry.get("response") or {}
            headers = {key.lower(): value for key, value in (response.get("headers") or {}).items()}
            status = int(response.get("status_code") or 0)
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        location = headers.get("location")
        if 300 <= status < 400 and isinstance(location, str) and location:
            found.append((endpoint, urljoin(endpoint, location)))
    return found


def is_document(url: str) -> bool:
    return PurePosixPath(unquote(urlparse(url).path)).suffix.lower() in DOCUMENT_EXTENSIONS


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
    """The URLs that point to a document on one of the allowed hosts, each document once.

    example.be and www.example.be usually serve the same site, so the crawl finds every
    document under both hosts. The same path is downloaded only once (the first host found),
    which avoids a duplicate finding per document and halves the downloads. This assumes both
    hosts serve the same file at the same path; a site where they differ would lose the
    document of the second host.
    """
    documents = []
    seen_paths = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed_hosts:
            continue
        path = (parsed.path, parsed.query)
        if is_document(url) and path not in seen_paths:
            seen_paths.add(path)
            documents.append(url)
    return documents
