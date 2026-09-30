"""Tests for the PDF report (#17): the text is read back from the generated PDF."""

import io
from datetime import UTC, datetime

from pypdf import PdfReader

from qnsentry.report.pdf import ReportData, ReportFinding, ReportModule, build_report

LOOKALIKE = ReportFinding(
    module="phishing",
    severity="high",
    title="Registered lookalike domain badsecuritylnc.be (can receive email)",
    description="This domain looks like the company domain and has a mail server.",
    asset="badsecuritylnc.be",
)
BREACH = ReportFinding(
    module="breach",
    severity="medium",
    title="sofie.maes@badsecurityinc.be appears in 1 data breach",
    description="This business email address appears in known data breaches.",
    asset="sofie.maes@badsecurityinc.be",
)
DKIM = ReportFinding(
    module="phishing",
    severity="low",
    title="No DKIM key found on badsecurityinc.be for common selectors",
    description="No DKIM key was found.",
    asset="badsecurityinc.be",
)


def report(findings, modules=None) -> ReportData:
    return ReportData(
        client="BadSecurityInc",
        domain="badsecurityinc.be",
        scan_id=7,
        status="completed",
        started_at=datetime(2026, 9, 30, 9, 0, tzinfo=UTC),
        generated_at=datetime(2026, 9, 30, 9, 30, tzinfo=UTC),
        modules=modules
        or [ReportModule(m, "completed") for m in ("attack_surface", "metadata", "phishing", "breach")],
        findings=findings,
    )


def text_of(pdf: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf))
    # Collapse whitespace: reportlab wraps long lines
    return " ".join(" ".join(page.extract_text() for page in reader.pages).split())


def test_report_is_a_pdf_with_the_client_domain_and_summary():
    pdf = build_report(report([LOOKALIKE, BREACH, DKIM]))

    assert pdf.startswith(b"%PDF")
    text = text_of(pdf)
    assert "External exposure report" in text
    assert "BadSecurityInc" in text and "badsecurityinc.be" in text
    assert "scan #7 of 30/09/2026" in text
    assert "found 3 findings" in text
    assert "1 of them is serious" in text


def test_important_findings_are_explained_and_others_listed():
    text = text_of(build_report(report([DKIM, BREACH, LOOKALIKE])))

    # Important findings: title and plain-language explanation, most severe first
    assert text.index("1. Registered lookalike domain") < text.index("2. sofie.maes@badsecurityinc.be")
    assert "has a mail server" in text
    # Low findings only in the "Other findings" table, not explained one by one
    assert "Other findings" in text
    assert "3. No DKIM key" not in text
    assert "No DKIM key found on badsecurityinc.be" in text


def test_summary_table_per_area():
    text = text_of(build_report(report([LOOKALIKE, BREACH, DKIM])))

    assert "Findings per area" in text
    for area in ("Attack surface", "Document metadata", "Phishing domains and email security", "Employee data breaches"):
        assert area in text


def test_failed_modules_are_reported_as_not_checked():
    modules = [
        ReportModule("attack_surface", "completed"),
        ReportModule("metadata", "failed", "katana is not installed in the worker image"),
        ReportModule("phishing", "completed"),
        ReportModule("breach", "completed"),
    ]

    text = text_of(build_report(report([LOOKALIKE], modules)))

    assert "Not everything could be checked" in text
    assert "document metadata did not complete" in text
    assert "Could not be completed: katana is not installed in the worker image" in text


def test_scan_without_findings_does_not_claim_the_organisation_is_secure():
    text = text_of(build_report(report([])))

    assert "found nothing an attacker could use" in text
    assert "does not prove that the organisation is secure" in text
    assert "No findings with a critical, high or medium severity" in text


def test_markup_characters_in_findings_are_shown_as_text():
    tricky = ReportFinding(
        module="metadata",
        severity="medium",
        title="budget.xlsx reveals <paths> & names",
        description=r"Internal path \\SRV-FS01\Finance\ found.",
        asset="https://badsecurityinc.be/files/budget.xlsx?a=1&b=2",
    )

    text = text_of(build_report(report([tricky])))

    assert "budget.xlsx reveals <paths> & names" in text
    assert r"\\SRV-FS01\Finance\ found." in text
