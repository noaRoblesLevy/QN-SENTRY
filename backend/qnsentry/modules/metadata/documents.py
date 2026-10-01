"""Download public documents with a size limit (issue #7)."""

import logging
import re
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

log = logging.getLogger(__name__)

MAX_DOCUMENTS = 50
MAX_BYTES = 20 * 1024 * 1024  # 20 MB per document
CHUNK = 64 * 1024
USER_AGENT = "QN-Sentry metadata check"
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def download_documents(urls: list[str], folder: Path, allowed_hosts: set[str]) -> dict[str, Path]:
    """Download up to MAX_DOCUMENTS documents into `folder`. A failing document is skipped."""
    downloaded: dict[str, Path] = {}
    for index, url in enumerate(urls[:MAX_DOCUMENTS]):
        target = folder / f"{index:03d}-{safe_name(url)}"
        try:
            if download(url, target, allowed_hosts):
                downloaded[url] = target
        except OSError as error:
            log.warning("Could not download %s: %s", url, error)
    if len(urls) > MAX_DOCUMENTS:
        log.warning("Only the first %s of %s documents were analysed", MAX_DOCUMENTS, len(urls))
    return downloaded


def download(url: str, target: Path, allowed_hosts: set[str]) -> bool:
    """Download one document; False when it is too large or redirects off the allowed hosts."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        if urlparse(response.geturl()).hostname not in allowed_hosts:
            log.warning("Skipped %s: redirects to another host", url)
            return False
        size = 0
        with open(target, "wb") as file:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > MAX_BYTES:
                    log.warning("Skipped %s: larger than %s bytes", url, MAX_BYTES)
                    file.close()
                    target.unlink(missing_ok=True)
                    return False
                file.write(chunk)
    return True


def safe_name(url: str) -> str:
    """A file name from the URL that is safe on disk, e.g. budget-2026.xlsx."""
    name = PurePosixPath(unquote(urlparse(url).path)).name or "document"
    return SAFE_NAME.sub("_", name)[-100:]
