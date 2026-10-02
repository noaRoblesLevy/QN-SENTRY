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
from qnsentry.modules.metadata import crawler, documents
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

    assert parse_katana_output(output) == (
        [
            "https://www.badsecurityinc.be/downloads.html",
            "https://www.badsecurityinc.be/files/budget-2026.xlsx",
        ],
        [],
    )


def test_katana_output_with_line_separators_inside_json_strings():
    # Office files in a response body can contain U+0085, which str.splitlines() splits on
    line = '{"request": {"endpoint": "https://www.badsecurityinc.be/files/deck.pptx"}, "note": "a\u0085b"}'

    assert parse_katana_output(line) == (["https://www.badsecurityinc.be/files/deck.pptx"], [])


def test_failed_requests_are_errors_not_endpoints():
    # What katana 1.7.0 prints for a host that does not exist (and it still exits with 0)
    line = (
        '{"request":{"method":"GET","endpoint":"https://bestaat-niet.invalid"},'
        '"error":"Get \\"https://bestaat-niet.invalid\\": cause=\\"no address found for host\\""}'
    )

    found, errors = parse_katana_output(line)

    assert found == []
    assert errors == ['https://bestaat-niet.invalid: Get "https://bestaat-niet.invalid": cause="no address found for host"']


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

    monkeypatch.setattr(metadata, "crawl", lambda urls, warn: [f"{SITE}/downloads.html", budget, privacy])
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts, warn: files)
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
    monkeypatch.setattr(metadata, "crawl", lambda urls, warn: [f"{SITE}/index.html"])
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts, warn: {})
    monkeypatch.setattr(metadata, "read_metadata", lambda paths: {})

    assert analyse_site([SITE], ScanContext(domain="badsecurityinc.be")) == []


def test_metadata_module_replaces_the_placeholder():
    assert isinstance(MODULES_BY_NAME["metadata"], MetadataModule)


def test_missing_tools_fail_the_module(monkeypatch):
    monkeypatch.setattr(crawler.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="katana is not installed"):
        crawler.crawl([SITE])


def fake_katana(monkeypatch, stdout="", stderr="", returncode=0, timeout=False):
    def run(command, **kwargs):
        if timeout:
            raise crawler.subprocess.TimeoutExpired(command, kwargs.get("timeout"))
        return crawler.subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(crawler.shutil, "which", lambda name: "/usr/local/bin/katana")
    monkeypatch.setattr(crawler.subprocess, "run", run)


def test_unreachable_website_fails_instead_of_looking_clean(monkeypatch):
    # Site offline, DNS or TLS error: "0 findings" would look like a clean site.
    # katana reports the failed start URL as a JSON line with "error" and exits with 0.
    fake_katana(
        monkeypatch,
        stdout='{"request": {"endpoint": "https://bestaat-niet.invalid"}, "error": "no address found for host"}\n',
    )

    with pytest.raises(RuntimeError, match="could not be crawled: .*no address found for host"):
        crawler.crawl(["https://bestaat-niet.invalid"])


def test_katana_error_message_on_stderr_is_used_when_there_is_no_output(monkeypatch):
    fake_katana(monkeypatch, stderr="[FTL] Could not create runner", returncode=1)

    with pytest.raises(RuntimeError, match="Could not create runner"):
        crawler.crawl([SITE])


def test_katana_timeout_fails_the_module(monkeypatch):
    fake_katana(monkeypatch, timeout=True)

    with pytest.raises(RuntimeError, match="did not finish"):
        crawler.crawl([SITE])


def test_crawl_returns_the_endpoints_katana_found(monkeypatch):
    fake_katana(monkeypatch, stdout=f'{{"request": {{"endpoint": "{SITE}/files/budget-2026.xlsx"}}}}\n')

    assert crawler.crawl([SITE]) == [f"{SITE}/files/budget-2026.xlsx"]


def test_read_metadata_of_no_files_needs_no_exiftool():
    assert read_metadata([]) == {}


# ---------- Warnings: a part failed, but the module still has results (#32) ----------


def test_start_url_that_cannot_be_reached_is_a_warning(monkeypatch):
    # badsecurityinc.be answers, www.badsecurityinc.be does not resolve
    fake_katana(
        monkeypatch,
        stdout="\n".join(
            [
                '{"request": {"endpoint": "https://badsecurityinc.be"}}',
                '{"request": {"endpoint": "https://www.badsecurityinc.be"}, "error": "no address found for host"}',
            ]
        ),
    )
    warnings = []

    found = crawler.crawl(["https://badsecurityinc.be", "https://www.badsecurityinc.be"], warn=warnings.append)

    assert found == ["https://badsecurityinc.be"]
    # Only the start URL warning: its error is not counted again as a failed page
    assert warnings == ["https://www.badsecurityinc.be could not be reached, so it was not crawled"]


def test_failed_pages_on_a_reachable_site_are_counted_in_one_warning(monkeypatch):
    fake_katana(
        monkeypatch,
        stdout="\n".join(
            [
                f'{{"request": {{"endpoint": "{SITE}"}}}}',
                f'{{"request": {{"endpoint": "{SITE}/a.html"}}, "error": "connection reset"}}',
                f'{{"request": {{"endpoint": "{SITE}/b.html"}}, "error": "timeout"}}',
            ]
        ),
    )
    warnings = []

    crawler.crawl([SITE], warn=warnings.append)

    assert warnings == ["2 request(s) failed during the crawl, so some pages may have been missed"]


def test_crawl_that_hits_its_time_limit_is_a_warning(monkeypatch):
    fake_katana(monkeypatch, stdout=f'{{"request": {{"endpoint": "{SITE}"}}}}\n')
    clock = iter([0.0, float(crawler.CRAWL_SECONDS)])
    monkeypatch.setattr(crawler.time, "monotonic", lambda: next(clock))
    warnings = []

    crawler.crawl([SITE], warn=warnings.append)

    assert warnings == [
        f"The crawl stopped at its limit of {crawler.CRAWL_SECONDS} s, "
        "so documents deeper in the website may have been missed"
    ]


def test_complete_crawl_has_no_warnings(monkeypatch):
    fake_katana(monkeypatch, stdout=f'{{"request": {{"endpoint": "{SITE}"}}}}\n')
    warnings = []

    crawler.crawl([SITE], warn=warnings.append)

    assert warnings == []


def test_skipped_documents_are_counted_per_reason_without_their_urls(monkeypatch, tmp_path):
    urls = [f"{SITE}/files/cv-jan-peeters.pdf", f"{SITE}/files/big.pdf", f"{SITE}/files/ok.pdf", f"{SITE}/files/gone.pdf"]
    answers = {
        urls[0]: OSError("connection reset"),
        urls[1]: "were skipped because they are larger than 20 MB",
        urls[2]: None,
        urls[3]: OSError("404"),
    }

    def fake_download(url, target, allowed_hosts):
        if isinstance(answers[url], OSError):
            raise answers[url]
        return answers[url]

    monkeypatch.setattr(documents, "download", fake_download)
    warnings = []

    downloaded = documents.download_documents(urls, tmp_path, {"www.badsecurityinc.be"}, warn=warnings.append)

    assert list(downloaded) == [urls[2]]
    assert warnings == [
        "2 of 4 document(s) could not be downloaded",
        "1 of 4 document(s) were skipped because they are larger than 20 MB",
    ]
    # Document names can contain personal data (GDPR): they stay out of the warnings
    assert not any("peeters" in w for w in warnings)


def test_documents_over_the_limit_are_a_warning(monkeypatch, tmp_path):
    urls = [f"{SITE}/files/{i}.pdf" for i in range(documents.MAX_DOCUMENTS + 5)]
    monkeypatch.setattr(documents, "download", lambda url, target, allowed_hosts: None)
    warnings = []

    documents.download_documents(urls, tmp_path, {"www.badsecurityinc.be"}, warn=warnings.append)

    assert warnings == [f"Only the first {documents.MAX_DOCUMENTS} of {documents.MAX_DOCUMENTS + 5} documents were analysed"]


def test_module_passes_its_warnings_to_the_scan_context(monkeypatch):
    def crawl(urls, warn):
        warn("https://www.badsecurityinc.be could not be reached, so it was not crawled")
        return [f"{SITE}/index.html"]

    monkeypatch.setattr(metadata, "crawl", crawl)
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts, warn: {})
    monkeypatch.setattr(metadata, "read_metadata", lambda paths: {})
    context = ScanContext(domain="badsecurityinc.be")

    MetadataModule().run(context)

    assert context.warnings == ["https://www.badsecurityinc.be could not be reached, so it was not crawled"]


def test_both_hosts_serving_the_same_site_is_not_a_warning(monkeypatch):
    # katana reports each page under one of the two hosts only; the other host was reached
    # too, so a host missing from the results must not be reported as unreachable
    fake_katana(monkeypatch, stdout='{"request": {"endpoint": "https://www.badsecurityinc.be/team.html"}}\n')
    warnings = []

    crawler.crawl(["https://badsecurityinc.be", "https://www.badsecurityinc.be"], warn=warnings.append)

    assert warnings == []


def test_max_depth_reached_is_not_a_failed_request(monkeypatch):
    # katana marks links deeper than MAX_DEPTH with "error", but that is the normal limit
    fake_katana(
        monkeypatch,
        stdout=(
            f'{{"request": {{"endpoint": "{SITE}"}}}}\n'
            f'{{"request": {{"endpoint": "{SITE}/deep.html"}}, "error": "max depth reached"}}\n'
        ),
    )
    warnings = []

    assert crawler.crawl([SITE], warn=warnings.append) == [SITE]
    assert warnings == []
