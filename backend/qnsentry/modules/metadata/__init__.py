"""Document Metadata Analysis (issue #7): what public documents reveal about the organisation.

1. Crawl the company website with katana, staying on the company's own hosts
2. Download the public documents (PDF, Office), with a limit on count and size
3. Read their metadata with exiftool and interpret it: people, usernames, software,
   internal paths and printer or scanner names
4. One finding per document that reveals something; author names go into the scan
   context for the Breach module (#12)
5. The email addresses published on the pages, and the naming convention they follow
   (#8, see emails.py); both go into the scan context for the Breach module
"""

import tempfile
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.metadata.crawler import crawl, document_urls, start_urls
from qnsentry.modules.metadata.documents import download_documents
from qnsentry.modules.metadata.emails import (
    collect_emails,
    detect_convention,
    to_address_finding,
    to_convention_finding,
)
from qnsentry.modules.metadata.extract import DocumentMetadata, interpret, read_metadata

MODULE = "metadata"
FINDING_TYPE = "document_metadata"


class MetadataModule(Module):
    name = MODULE

    def run(self, context: ScanContext) -> list[Finding]:
        return analyse_site(start_urls(context.domain), context)


def analyse_site(urls: list[str], context: ScanContext) -> list[Finding]:
    """Crawl `urls`, analyse the documents and email addresses found there, and add the
    author names, addresses and naming convention to `context`."""
    allowed_hosts = {urlparse(url).hostname for url in urls}
    found = crawl(urls, warn=context.warn)
    documents = document_urls(found, allowed_hosts)

    findings: list[Finding] = []
    # Documents are only kept while they are analysed (GDPR: nothing is stored)
    with tempfile.TemporaryDirectory(prefix="qnsentry-documents-") as folder:
        files = download_documents(documents, Path(folder), allowed_hosts, warn=context.warn)
        tags_per_file = read_metadata(list(files.values()))

        for url, path in files.items():
            tags = tags_per_file.get(path)
            if not tags:
                continue
            meta = interpret(tags)
            for person in meta.people:
                if person not in context.person_names:
                    context.person_names.append(person)
            if not meta.is_empty():
                findings.append(to_finding(url, meta))

    # The command-line tool can crawl a start URL without a domain: use its host then
    domain = context.domain or (urlparse(urls[0]).hostname or "").removeprefix("www.")
    emails = collect_emails(found, allowed_hosts, domain, warn=context.warn)
    for address in emails:
        if address not in context.emails:
            context.emails.append(address)
    if emails:
        findings.append(to_address_finding(emails, domain))

    convention = detect_convention(context.person_names, list(emails), domain)
    if convention:
        context.email_convention = convention.convention
        context.last_name_style = convention.last_name_style
        findings.append(to_convention_finding(convention, domain, names_checked=len(context.person_names)))
    return findings


def to_finding(url: str, meta: DocumentMetadata) -> Finding:
    file = PurePosixPath(unquote(urlparse(url).path)).name or url
    revealed = []
    explanation = []

    if meta.internal_paths:
        revealed.append("internal file paths")
        explanation.append(
            "Internal file paths and server names show how the internal network and file shares "
            "are organised, which helps an attacker who gets inside."
        )
    if meta.usernames:
        revealed.append("usernames")
        explanation.append("Usernames reveal the format of login names, which helps to guess passwords.")
    if meta.people:
        revealed.append("names of employees")
        explanation.append("Names of employees can be used for targeted phishing emails.")
    if meta.outdated_software:
        revealed.append("outdated software")
        explanation.append(
            "The document was made with software that no longer receives security updates, "
            "which suggests it is still in use."
        )
    elif meta.software:
        revealed.append("software versions")
    if meta.devices:
        revealed.append("printer or scanner names")
        explanation.append("Printer and scanner names reveal devices on the internal network.")

    description = " ".join(
        [
            "The metadata of this public document reveals information that the document itself "
            "does not show.",
            *explanation,
            "Remove metadata before publishing documents, e.g. with 'Inspect Document' in Office.",
        ]
    )
    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=f"{file} reveals {join_words(revealed)}",
        description=description,
        # Internal paths are the most useful for an attacker (data contract 10.2)
        severity=Severity.MEDIUM if meta.internal_paths else Severity.LOW,
        asset=url,
        details={"url": url, "file": file, **asdict(meta)},
    )


def join_words(words: list[str]) -> str:
    """["a", "b", "c"] -> "a, b and c" """
    if len(words) <= 1:
        return "".join(words)
    return f"{', '.join(words[:-1])} and {words[-1]}"
