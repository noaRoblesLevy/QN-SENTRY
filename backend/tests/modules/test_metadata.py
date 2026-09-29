"""Tests for the metadata module (#7). No network, katana or exiftool needed.

The exiftool tags below follow the documents planted on the BadSecurityInc website
(testenv/website/README.md).
"""

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules import MODULES_BY_NAME
from qnsentry.modules import metadata
from qnsentry.modules.base import ScanContext
from qnsentry.modules.metadata import MetadataModule, analyse_site, join_words, to_finding
from qnsentry.modules.metadata import crawler
from qnsentry.modules.metadata.crawler import document_urls, parse_katana_output
from qnsentry.modules.metadata.documents import safe_name
from qnsentry.modules.metadata.extract import interpret, read_metadata

SITE = "https://www.badsecurityinc.be"
HOSTS = {"badsecurityinc.be", "www.badsecurityinc.be"}

BUDGET_XLSX = {
    "FileType": "XLSX",
    "Creator": "Pieter Mertens",
    "LastModifiedBy": "Sofie Maes",
    "Application": "Microsoft Excel",
    "AppVersion": 12.0,
    "Company": "BadSecurityInc",
    "HyperlinkBase": "\\\\SRV-FS01\\Finance\\Budget\\",
}
VACANCY_DOCX = {
    "FileType": "DOCX",
    "Creator": "Lars Janssens",
    "LastModifiedBy": "BSI\\ljanssens",
    "Application": "Microsoft Office Word",
    "AppVersion": "14.0000",
    "Template": "\\\\SRV-FS01\\Templates\\BSI-letterhead.dotx",
}
TERMS_PDF = {
    "FileType": "PDF",
    "Author": "jpeeters",
    "Title": "Microsoft Word - terms and conditions v4.docx",
    "Creator": "Microsoft® Word 2010",
    "Producer": "Microsoft® Word 2010",
}
POLICY_PDF = {
    "FileType": "PDF",
    "Author": "Lars Janssens",
    "Subject": "Draft, internal use only",
    "Keywords": "C:\\Users\\ljanssens\\Documents\\Policies",
    "Creator": "Microsoft® Word 2013",
    "Producer": "Microsoft® Word 2013",
}
SCANNED_PDF = {"FileType": "PDF", "Creator": "BSI-MFP-2F", "Producer": "KONICA MINOLTA bizhub C308"}
CLEAN_PDF = {
    "SourceFile": "/tmp/qnsentry-documents-x/011-privacy-notice.pdf",
    "Directory": "/tmp/qnsentry-documents-x",
    "FileType": "PDF",
    "PDFVersion": "1.4",
    "PageCount": 1,
}


# ---------- Interpreting exiftool tags ----------


def test_office_file_reveals_people_outdated_office_and_an_internal_path():
    meta = interpret(BUDGET_XLSX)

    assert meta.people == ["Pieter Mertens", "Sofie Maes"]
    assert meta.software == ["Microsoft Excel 2007"]
    assert meta.outdated_software == ["Microsoft Excel 2007"]
    assert meta.internal_paths == ["\\\\SRV-FS01\\Finance\\Budget\\"]
    assert meta.servers == ["SRV-FS01"]


def test_domain_username_and_template_path_in_a_word_file():
    meta = interpret(VACANCY_DOCX)

    assert meta.people == ["Lars Janssens"]
    assert meta.usernames == ["BSI\\ljanssens"]
    assert meta.software == ["Microsoft Office Word 2010"]
    assert meta.internal_paths == ["\\\\SRV-FS01\\Templates\\BSI-letterhead.dotx"]


def test_pdf_creator_is_software_and_a_single_word_author_is_a_username():
    meta = interpret(TERMS_PDF)

    assert meta.people == []
    assert meta.usernames == ["jpeeters"]
    assert meta.software == ["Microsoft® Word 2010"]
    assert meta.outdated_software == ["Microsoft® Word 2010"]


def test_windows_profile_path_reveals_the_username():
    meta = interpret(POLICY_PDF)

    assert meta.internal_paths == ["C:\\Users\\ljanssens\\Documents\\Policies"]
    assert meta.usernames == ["ljanssens"]
    assert meta.people == ["Lars Janssens"]


def test_scanned_pdf_reveals_printer_model_and_device_name():
    meta = interpret(SCANNED_PDF)

    assert meta.devices == ["KONICA MINOLTA bizhub C308", "BSI-MFP-2F"]
    assert meta.software == []


def test_cleaned_document_reveals_nothing():
    # The download folder in SourceFile and Directory is ours, not a leak of the client
    assert interpret(CLEAN_PDF).is_empty()


def test_office_2016_or_later_is_not_outdated():
    meta = interpret({"FileType": "PPTX", "Application": "Microsoft Office PowerPoint", "AppVersion": "16.0000"})

    assert meta.software == ["Microsoft Office PowerPoint 2016 or later"]
    assert meta.outdated_software == []


# ---------- Findings ----------


def test_internal_paths_make_a_medium_finding():
    finding = to_finding(f"{SITE}/files/budget-2026.xlsx", interpret(BUDGET_XLSX))

    assert finding.severity == Severity.MEDIUM
    assert finding.module == "metadata"
    assert finding.type == "document_metadata"
    assert finding.asset == f"{SITE}/files/budget-2026.xlsx"
    assert finding.title == "budget-2026.xlsx reveals internal file paths, names of employees and outdated software"
    assert finding.details["servers"] == ["SRV-FS01"]


def test_names_and_usernames_without_paths_make_a_low_finding():
    finding = to_finding(f"{SITE}/files/terms-and-conditions.pdf", interpret(TERMS_PDF))

    assert finding.severity == Severity.LOW
    assert finding.title == "terms-and-conditions.pdf reveals usernames and outdated software"


def test_join_words():
    assert join_words(["a"]) == "a"
    assert join_words(["a", "b", "c"]) == "a, b and c"


# ---------- Crawling and downloading ----------


def test_katana_output_is_parsed_without_duplicates():
    output = "\n".join(
        [
            '{"request": {"endpoint": "https://www.badsecurityinc.be/downloads.html"}}',
            '{"request": {"endpoint": "https://www.badsecurityinc.be/files/budget-2026.xlsx"}}',
            '{"request": {"endpoint": "https://www.badsecurityinc.be/downloads.html"}}',
            "",
            "not json",
        ]
    )

    assert parse_katana_output(output) == [
        "https://www.badsecurityinc.be/downloads.html",
        "https://www.badsecurityinc.be/files/budget-2026.xlsx",
    ]


def test_katana_output_with_line_separators_inside_json_strings():
    # Office files in a response body can contain U+0085, which str.splitlines() splits on
    line = '{"request": {"endpoint": "https://www.badsecurityinc.be/files/deck.pptx"}, "note": "a\u0085b"}'

    assert parse_katana_output(line) == ["https://www.badsecurityinc.be/files/deck.pptx"]


def test_only_documents_on_the_clients_own_hosts_are_kept():
    urls = [
        f"{SITE}/index.html",
        f"{SITE}/files/budget-2026.xlsx",
        f"{SITE}/files/Annual%20Report.PDF?download=1",
        "https://cdn.example.net/whitepaper.pdf",  # another host
        "mailto:info@badsecurityinc.be",
    ]

    assert document_urls(urls, HOSTS) == [
        f"{SITE}/files/budget-2026.xlsx",
        f"{SITE}/files/Annual%20Report.PDF?download=1",
    ]


def test_safe_name_keeps_the_file_name_only():
    assert safe_name(f"{SITE}/files/budget-2026.xlsx") == "budget-2026.xlsx"
    assert safe_name(f"{SITE}/files/Annual%20Report.pdf") == "Annual_Report.pdf"
    assert safe_name(f"{SITE}/") == "document"


# ---------- The module ----------


def test_module_analyses_documents_and_fills_the_context(monkeypatch, tmp_path):
    budget = f"{SITE}/files/budget-2026.xlsx"
    privacy = f"{SITE}/files/privacy-notice.pdf"
    files = {budget: tmp_path / "000-budget-2026.xlsx", privacy: tmp_path / "001-privacy-notice.pdf"}

    monkeypatch.setattr(metadata, "crawl", lambda urls: [f"{SITE}/downloads.html", budget, privacy])
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts: files)
    monkeypatch.setattr(
        metadata, "read_metadata", lambda paths: {files[budget]: BUDGET_XLSX, files[privacy]: CLEAN_PDF}
    )
    context = ScanContext(domain="badsecurityinc.be", person_names=["Sofie Maes"])

    findings = MetadataModule().run(context)

    # The cleaned privacy notice gives no finding
    assert [f.asset for f in findings] == [budget]
    # Author names are passed on for the Breach module (#12), without duplicates
    assert context.person_names == ["Sofie Maes", "Pieter Mertens"]


def test_site_without_documents_gives_no_findings(monkeypatch):
    monkeypatch.setattr(metadata, "crawl", lambda urls: [f"{SITE}/index.html"])
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts: {})
    monkeypatch.setattr(metadata, "read_metadata", lambda paths: {})

    assert analyse_site([SITE], ScanContext(domain="badsecurityinc.be")) == []


def test_metadata_module_replaces_the_placeholder():
    assert isinstance(MODULES_BY_NAME["metadata"], MetadataModule)


def test_missing_tools_fail_the_module(monkeypatch):
    monkeypatch.setattr(crawler.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="katana is not installed"):
        crawler.crawl([SITE])


def test_read_metadata_of_no_files_needs_no_exiftool():
    assert read_metadata([]) == {}
