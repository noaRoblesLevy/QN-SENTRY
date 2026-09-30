"""Read document metadata with exiftool and interpret it (issue #7).

read_metadata() runs exiftool; interpret() only looks at the values exiftool returned,
so it is tested without exiftool or network.

exiftool uses the same tag names for different things depending on the file type:
in a PDF, "Creator" is the program that made the file; in an Office file, "Creator"
is the author. So the interpretation depends on the file type.
"""

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Tags that name people, per kind of file
PDF_PERSON_TAGS = ("Author",)
OFFICE_PERSON_TAGS = ("Creator", "Author", "LastModifiedBy")
# Tags that name the program that made the file
PDF_SOFTWARE_TAGS = ("Creator", "Producer")
OFFICE_SOFTWARE_TAGS = ("Software",)
PDF_TYPES = {"PDF"}

# Tags that describe the file on disk after downloading, not the document itself
IGNORED_TAGS = {"SourceFile", "FileName", "Directory", "FilePermissions", "ExifToolVersion"}

# \\SERVER\share\... and C:\folder\...
UNC_PATH = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\s\"<>|]*")
LOCAL_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"<>|]*")
# DOMAIN\user
DOMAIN_USER = re.compile(r"^[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+$")
# C:\Users\<name>\...
PROFILE_PATH = re.compile(r"\b[A-Za-z]:\\Users\\([^\\\s]+)", re.IGNORECASE)
# A single word without spaces, e.g. "jpeeters", in a field meant for a name
USERNAME_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{1,31}$")

# Printer and scanner vendors that write their model into scanned PDFs
DEVICE_VENDORS = (
    "konica", "minolta", "ricoh", "xerox", "canon", "kyocera", "brother",
    "lexmark", "epson", "sharp", "toshiba", "hp ", "hewlett",
)

# Office "AppVersion" major number -> release; 16 covers 2016, 2019, 2021 and Microsoft 365
OFFICE_RELEASES = {11: "2003", 12: "2007", 14: "2010", 15: "2013", 16: "2016 or later"}
# Office versions that no longer receive security updates
OUTDATED_OFFICE_RELEASES = {"2003", "2007", "2010", "2013"}
OUTDATED_IN_NAME = re.compile(r"\bMicrosoft\b.*\b(2003|2007|2010|2013)\b", re.IGNORECASE)


@dataclass
class DocumentMetadata:
    """What the metadata of one document reveals."""

    people: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    software: list[str] = field(default_factory=list)
    outdated_software: list[str] = field(default_factory=list)
    internal_paths: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.people or self.usernames or self.software or self.internal_paths or self.devices)


def read_metadata(files: list[Path]) -> dict[Path, dict]:
    """exiftool output per file. Raises when exiftool is not installed."""
    if not files:
        return {}
    if shutil.which("exiftool") is None:
        raise RuntimeError("exiftool is not installed in the worker image")

    result = subprocess.run(
        ["exiftool", "-json", "-charset", "filename=utf8", *[str(f) for f in files]],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    # exiftool exits with 1 when a single file cannot be read, but still prints the others
    if not result.stdout.strip():
        return {}
    return {Path(entry["SourceFile"]): entry for entry in json.loads(result.stdout)}


def interpret(tags: dict) -> DocumentMetadata:
    """Turn the exiftool tags of one document into people, usernames, software, paths and devices."""
    meta = DocumentMetadata()
    is_pdf = str(tags.get("FileType", "")).upper() in PDF_TYPES

    for tag in PDF_PERSON_TAGS if is_pdf else OFFICE_PERSON_TAGS:
        _add_person_or_username(meta, tags.get(tag))

    for tag in PDF_SOFTWARE_TAGS if is_pdf else OFFICE_SOFTWARE_TAGS:
        _add_software_or_device(meta, tags.get(tag))
    if not is_pdf:
        _add(meta.software, _office_application(tags))

    if meta.devices and is_pdf:
        # A scanned PDF: the Creator next to a printer model is the device name (e.g. BSI-MFP-2F)
        creator = _text(tags.get("Creator"))
        if creator and creator in meta.software:
            meta.software.remove(creator)
            _add(meta.devices, creator)

    for tag, value in tags.items():
        if tag not in IGNORED_TAGS:
            _add_paths(meta, _text(value))

    for name in meta.software:
        if OUTDATED_IN_NAME.search(name) or any(name.endswith(f" {r}") for r in OUTDATED_OFFICE_RELEASES):
            _add(meta.outdated_software, name)
    return meta


# ---------- Helpers ----------


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value).strip()


def _add(target: list[str], value: str | None) -> None:
    if value and value not in target:
        target.append(value)


def _add_person_or_username(meta: DocumentMetadata, value) -> None:
    text = _text(value)
    if not text:
        return
    if DOMAIN_USER.match(text):
        _add(meta.usernames, text)
    elif " " in text:
        _add(meta.people, text)
    elif USERNAME_LIKE.match(text):
        _add(meta.usernames, text)


def _add_software_or_device(meta: DocumentMetadata, value) -> None:
    text = _text(value)
    if not text:
        return
    if any(vendor in f"{text.lower()} " for vendor in DEVICE_VENDORS):
        _add(meta.devices, text)
    else:
        _add(meta.software, text)


def _office_application(tags: dict) -> str | None:
    application = _text(tags.get("Application"))
    if not application:
        return None
    try:
        major = int(float(_text(tags.get("AppVersion"))))
    except ValueError:
        return application
    release = OFFICE_RELEASES.get(major)
    return f"{application} {release}" if release else application


def _add_paths(meta: DocumentMetadata, text: str) -> None:
    for path in UNC_PATH.findall(text) + LOCAL_PATH.findall(text):
        _add(meta.internal_paths, path)
        if path.startswith("\\\\"):
            _add(meta.servers, path[2:].split("\\", 1)[0])
    for user in PROFILE_PATH.findall(text):
        _add(meta.usernames, user)
