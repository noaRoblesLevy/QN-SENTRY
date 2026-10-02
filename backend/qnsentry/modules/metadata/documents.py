"""Download public documents with a size limit (issue #7)."""

import logging
import re
import urllib.request
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

log = logging.getLogger(__name__)

MAX_DOCUMENTS = 50
MAX_BYTES = 20 * 1024 * 1024  # 20 MB per document
CHUNK = 64 * 1024
USER_AGENT = "QN-Sentry metadata check"
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def download_documents(
    urls: list[str], folder: Path, allowed_hosts: set[str], warn: Callable[[str], None] = lambda message: None
) -> dict[str, Path]:
    """Download up to MAX_DOCUMENTS documents into `folder`. A failing document is skipped.

    Skipped documents are reported to `warn` as a count per reason: the document URLs
    can contain names (cv-jan-peeters.pdf), so they are only logged.
    """
    downloaded: dict[str, Path] = {}
    skipped: Counter[str] = Counter()
    for index, url in enumerate(urls[:MAX_DOCUMENTS]):
        target = folder / f"{index:03d}-{safe_name(url)}"
        try:
            reason = download(url, target, allowed_hosts)
        except OSError as error:
            log.warning("Could not download %s: %s", url, error)
            reason = "could not be downloaded"
        if reason:
            skipped[reason] += 1
        else:
            downloaded[url] = target

    for reason, count in skipped.items():
        warn(f"{count} of {min(len(urls), MAX_DOCUMENTS)} document(s) {reason}")
    if len(urls) > MAX_DOCUMENTS:
        log.warning("Only the first %s of %s documents were analysed", MAX_DOCUMENTS, len(urls))
        warn(f"Only the first {MAX_DOCUMENTS} of {len(urls)} documents were analysed")
    return downloaded


def download(url: str, target: Path, allowed_hosts: set[str]) -> str | None:
    """Download one document; the reason it was skipped, or None when it was downloaded."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        if urlparse(response.geturl()).hostname not in allowed_hosts:
            log.warning("Skipped %s: redirects to another host", url)
            return "were skipped because they redirect to another website"
        size = 0
        with open(target, "wb") as file:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > MAX_BYTES:
                    log.warning("Skipped %s: larger than %s bytes", url, MAX_BYTES)
                    file.close()
                    target.unlink(missing_ok=True)
                    return f"were skipped because they are larger than {MAX_BYTES // (1024 * 1024)} MB"
                file.write(chunk)
    return None


def safe_name(url: str) -> str:
    """A file name from the URL that is safe on disk, e.g. budget-2026.xlsx."""
    name = PurePosixPath(unquote(urlparse(url).path)).name or "document"
    return SAFE_NAME.sub("_", name)[-100:]
