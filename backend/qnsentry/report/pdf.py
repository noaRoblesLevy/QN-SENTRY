"""Build the PDF summary report of a scan (issue #17).

The report is written for management, not for IT: it starts with what matters most and
explains every important finding in plain language (the finding's `description`, data
contract 10.1). Technical details stay in the dashboard.

build_report() only works on the plain data in ReportData, so it is tested without a
database. The API turns a scan from the database into ReportData. A failed scan gets no
report (the API answers 409): it has no results, and a report would look like a clean bill
of health.

The text uses the bundled DejaVu fonts (fonts/README.md): the built-in PDF fonts only
cover Latin characters, and homoglyph lookalikes use Cyrillic or Greek letters.
"""

import io
from collections import Counter
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

FONT_FOLDER = Path(__file__).resolve().parent / "fonts"
SANS, SANS_BOLD, MONO, MONO_BOLD = "DejaVuSans", "DejaVuSans-Bold", "DejaVuSansMono", "DejaVuSansMono-Bold"


def _register_fonts() -> None:
    for name in (SANS, SANS_BOLD, MONO, MONO_BOLD):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(FONT_FOLDER / f"{name}.ttf")))
    # So <b> inside a paragraph switches to the bold file
    pdfmetrics.registerFontFamily(SANS, normal=SANS, bold=SANS_BOLD, italic=SANS, boldItalic=SANS_BOLD)
    pdfmetrics.registerFontFamily(MONO, normal=MONO, bold=MONO_BOLD, italic=MONO, boldItalic=MONO_BOLD)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
# Important findings are explained one by one; the others are listed in a table
IMPORTANT = {"critical", "high", "medium"}

MODULES = ["attack_surface", "metadata", "phishing", "breach"]
MODULE_LABELS = {
    "attack_surface": "Attack surface",
    "metadata": "Document metadata",
    "phishing": "Phishing domains and email security",
    "breach": "Employee data breaches",
}

# Light theme of the QN-SENTRY design system (reports are printed)
INK = colors.HexColor("#0f1720")
MUTED = colors.HexColor("#4f5d6c")
LINE = colors.HexColor("#dde3ea")
RAISED = colors.HexColor("#f8fafc")
SIGNAL = colors.HexColor("#0a7a72")
SEVERITY_COLORS = {
    "critical": (colors.HexColor("#b8182f"), colors.HexColor("#fde8ea")),
    "high": (colors.HexColor("#a8430a"), colors.HexColor("#fdeede")),
    "medium": (colors.HexColor("#7d5b00"), colors.HexColor("#fbf2d6")),
    "low": (colors.HexColor("#1d5cb8"), colors.HexColor("#e4eefc")),
    "info": (colors.HexColor("#4f5d6c"), colors.HexColor("#eef1f4")),
}


@dataclass
class ReportFinding:
    """A finding, in the order the module reported it (the API passes them by id)."""

    module: str
    severity: str
    title: str
    description: str
    asset: str


@dataclass
class ReportModule:
    module: str
    status: str  # completed, failed, ...
    error: str | None = None
    # Parts that failed while the module still had results (#32)
    warnings: list[str] = field(default_factory=list)
    # False for a module that does not exist yet in this version (a placeholder, #1)
    available: bool = True


@dataclass
class ReportData:
    client: str
    domain: str
    scan_id: int
    status: str
    started_at: datetime
    generated_at: datetime
    modules: list[ReportModule] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    # Sources the report must credit, e.g. Have I Been Pwned (CC BY 4.0)
    attributions: list[str] = field(default_factory=list)


def build_report(data: ReportData) -> bytes:
    if data.status == "failed":
        raise ValueError("A failed scan has no results to report")
    _register_fonts()
    styles = _styles()
    story = []

    # ---------- Title ----------
    story += [
        Paragraph("QN-SENTRY", styles["brand"]),
        Paragraph("External exposure report", styles["title"]),
        Paragraph(
            f"{_x(data.client)} &middot; <font name='DejaVuSansMono'>{_x(data.domain)}</font> &middot; "
            f"scan #{data.scan_id} of {data.started_at:%d/%m/%Y}",
            styles["meta"],
        ),
        Spacer(1, 6 * mm),
    ]

    counts = Counter(f.severity for f in data.findings)
    failed = [m for m in data.modules if m.status == "failed" and m.available]
    unavailable = [m for m in data.modules if not m.available]

    # ---------- Summary ----------
    story += [Paragraph("Summary", styles["h1"]), Paragraph(_summary_text(data, counts), styles["body"])]
    if failed or unavailable:
        reasons = []
        if failed:
            reasons.append(f"{_names(failed)} did not complete")
        if unavailable:
            verb = "is" if len(unavailable) == 1 else "are"
            reasons.append(f"{_names(unavailable)} {verb} not available in this version of QN-Sentry")
        story.append(
            Paragraph(
                f"<b>Not everything could be checked:</b> {_x('; '.join(reasons))}, so this report may be "
                "incomplete for that part. See 'Scope' at the end.",
                styles["body"],
            )
        )
    story += [Spacer(1, 3 * mm), _severity_tiles(counts), Spacer(1, 6 * mm)]

    # ---------- Findings per area ----------
    story += [
        Paragraph("Findings per area", styles["h1"]),
        _module_table(data, styles),
        Spacer(1, 6 * mm),
    ]

    # ---------- Important findings ----------
    important = _sorted([f for f in data.findings if f.severity in IMPORTANT])
    story.append(Paragraph("What needs attention", styles["h1"]))
    if important:
        story.append(
            Paragraph(
                "These findings are the most useful to an attacker. Each one explains what it means and "
                "what to do about it.",
                styles["intro"],
            )
        )
        for number, finding in enumerate(important, start=1):
            story.append(_finding_block(number, finding, styles))
    else:
        story.append(Paragraph("No findings with a critical, high or medium severity.", styles["body"]))

    # ---------- Other findings ----------
    others = _sorted([f for f in data.findings if f.severity not in IMPORTANT])
    if others:
        story += [
            Spacer(1, 4 * mm),
            Paragraph("Other findings", styles["h1"]),
            Paragraph(
                "Low-risk and informational findings: good to know, and useful for IT to review.",
                styles["intro"],
            ),
            _others_table(others, styles),
        ]

    # ---------- Scope ----------
    story += [Spacer(1, 6 * mm), Paragraph("Scope and method", styles["h1"])]
    story.append(
        Paragraph(
            f"QN-Sentry looked at <font name='DejaVuSansMono'>{_x(data.domain)}</font> from the outside, the way an "
            "attacker would before an attack: public sources, DNS records, the public website and its "
            "documents, and known data breaches. It did not try to break in, log in or test passwords "
            "(see the legal and ethical framework). The results show the situation on the day of the scan.",
            styles["intro"],
        )
    )
    story.append(_scope_table(data, styles))
    if data.attributions:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("Sources: " + "; ".join(_x(a) for a in data.attributions) + ".", styles["body"]))

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"QN-Sentry report {data.domain}",
        author="QN-Sentry",
        subject=f"External exposure report for {data.client}",
    )

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(SANS, 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"Confidential: {data.client} | generated {data.generated_at:%d/%m/%Y %H:%M} UTC")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


# ---------- Parts ----------


def _summary_text(data: ReportData, counts: Counter) -> str:
    total = sum(counts.values())
    if total == 0:
        where = (
            "in the parts that could be checked"
            if any(m.status == "failed" or not m.available for m in data.modules)
            else "from the outside"
        )
        return (
            f"QN-Sentry found nothing an attacker could use about {_x(data.client)} {where}. "
            "This does not prove that the organisation is secure, only that no weaknesses were visible "
            "with the checks in this report."
        )
    urgent = counts["critical"] + counts["high"]
    text = f"QN-Sentry found <b>{total} finding{'s' if total != 1 else ''}</b> about {_x(data.client)}. "
    if urgent:
        text += (
            f"<b>{urgent}</b> of them {'are' if urgent != 1 else 'is'} serious (critical or high) and should be "
            f"fixed soon: {'they are' if urgent != 1 else 'it is'} listed first under 'What needs attention'."
        )
    elif counts["medium"]:
        text += "None of them is serious, but the medium findings should be fixed."
    else:
        text += "All of them are low risk or informational."
    return text


def _severity_tiles(counts: Counter) -> Table:
    cells = []
    for severity in SEVERITIES:
        fg, _ = SEVERITY_COLORS[severity]
        cells.append(
            Paragraph(
                f"<font size='18' color='{fg.hexval()}'><b>{counts[severity]}</b></font><br/>"
                f"<font size='8' color='{fg.hexval()}'>{SEVERITY_LABELS[severity].upper()}</font>",
                ParagraphStyle("tile", fontName=SANS, alignment=1, leading=16),
            )
        )
    table = Table([cells], colWidths=[34 * mm] * 5, rowHeights=[16 * mm])
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.5, LINE)]
    for index, severity in enumerate(SEVERITIES):
        style.append(("BACKGROUND", (index, 0), (index, 0), SEVERITY_COLORS[severity][1]))
        style.append(("LINEAFTER", (index, 0), (index, 0), 0.5, colors.white))
    table.setStyle(TableStyle(style))
    return table


def _module_table(data: ReportData, styles) -> Table:
    header = ["Area", *[SEVERITY_LABELS[s] for s in SEVERITIES], "Total"]
    rows = [header]
    runs = {m.module: m for m in data.modules}
    for module in MODULES:
        found = [f for f in data.findings if f.module == module]
        per = Counter(f.severity for f in found)
        label = MODULE_LABELS[module]
        run = runs.get(module)
        if run is not None and not run.available:
            label += " (not available)"
        elif run is not None and run.status == "failed":
            label += " (not completed)"
        rows.append([Paragraph(_x(label), styles["cell"]), *[per[s] or "" for s in SEVERITIES], len(found)])
    totals = Counter(f.severity for f in data.findings)
    rows.append(["Total", *[totals[s] or "" for s in SEVERITIES], len(data.findings)])

    table = Table(rows, colWidths=[62 * mm] + [17 * mm] * 5 + [19 * mm], repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), SANS_BOLD, 8),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("BACKGROUND", (0, 0), (-1, 0), RAISED),
        ("FONT", (0, 1), (-1, -1), SANS, 9),
        ("FONT", (0, -1), (-1, -1), SANS_BOLD, 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for index, severity in enumerate(SEVERITIES, start=1):
        style.append(("TEXTCOLOR", (index, 1), (index, -1), SEVERITY_COLORS[severity][0]))
    table.setStyle(TableStyle(style))
    return table


def _finding_block(number: int, finding: ReportFinding, styles) -> KeepTogether:
    fg, bg = SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["info"])
    badge = Table(
        [[Paragraph(f"<font color='{fg.hexval()}'><b>{SEVERITY_LABELS.get(finding.severity, finding.severity).upper()}</b></font>", styles["badge"])]],
        colWidths=[22 * mm],
        style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]),
    )
    heading = Table(
        [[badge, Paragraph(f"<b>{number}. {_x(finding.title)}</b>", styles["finding_title"])]],
        colWidths=[25 * mm, None],
        style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
    )
    return KeepTogether(
        [
            Spacer(1, 3 * mm),
            heading,
            Paragraph(_x(finding.description), styles["finding_text"]),
            Paragraph(
                f"{_x(MODULE_LABELS.get(finding.module, finding.module))} &middot; "
                f"<font name='DejaVuSansMono'>{_x(finding.asset)}</font>",
                styles["finding_meta"],
            ),
        ]
    )


def _others_table(findings: list[ReportFinding], styles) -> Table:
    rows = [["Severity", "Finding"]]
    for f in findings:
        # The asset under the title: the ASCII form (xn--...) of a homoglyph lookalike, a URL, ...
        cell = (
            f"{_x(f.title)}<br/><font name='DejaVuSansMono' size='7.5' color='{MUTED.hexval()}'>{_x(f.asset)}</font>"
        )
        rows.append([SEVERITY_LABELS.get(f.severity, f.severity), Paragraph(cell, styles["cell"])])
    table = Table(rows, colWidths=[22 * mm, None], repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), SANS_BOLD, 8),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("BACKGROUND", (0, 0), (-1, 0), RAISED),
        ("FONT", (0, 1), (0, -1), SANS_BOLD, 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
    ]
    for row, f in enumerate(findings, start=1):
        style.append(("TEXTCOLOR", (0, row), (0, row), SEVERITY_COLORS.get(f.severity, SEVERITY_COLORS["info"])[0]))
    table.setStyle(TableStyle(style))
    return table


def _scope_table(data: ReportData, styles) -> Table:
    rows = [["Area", "Result"]]
    statuses = {m.module: m for m in data.modules}
    for module in MODULES:
        run = statuses.get(module)
        if run is None:
            result = "Not part of this scan"
        elif not run.available:
            result = "Not available in this version of QN-Sentry: not checked"
        elif run.status == "failed":
            result = f"Could not be completed: {run.error or 'unknown error'}"
        elif run.warnings:
            result = "Checked, with warnings: " + " ".join(_sentence(w) for w in run.warnings)
        else:
            result = "Checked"
        rows.append([Paragraph(_x(MODULE_LABELS[module]), styles["cell"]), Paragraph(_x(result), styles["cell"])])
    table = Table(rows, colWidths=[62 * mm, None], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), SANS_BOLD, 8),
                ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
                ("BACKGROUND", (0, 0), (-1, 0), RAISED),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
            ]
        )
    )
    return table


# ---------- Helpers ----------


def _sorted(findings: list[ReportFinding]) -> list[ReportFinding]:
    """By severity, then by module; within that the module's own order is kept (sorted() is
    stable), so e.g. the lookalike that can receive email comes before the email records."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITIES.index(f.severity) if f.severity in SEVERITIES else len(SEVERITIES),
            MODULES.index(f.module) if f.module in MODULES else len(MODULES),
        ),
    )


def _names(modules: list[ReportModule]) -> str:
    return " and ".join(MODULE_LABELS.get(m.module, m.module).lower() for m in modules)


def _sentence(text: str) -> str:
    return text if text.endswith((".", "!", "?")) else f"{text}."


def _x(text: str) -> str:
    """Escape text for reportlab's Paragraph markup (it reads <b>, &amp;, ...)."""
    return escape(str(text))


def _styles() -> dict[str, ParagraphStyle]:
    base = dict(fontName=SANS, textColor=INK, alignment=TA_LEFT)
    return {
        "brand": ParagraphStyle("brand", fontName=MONO_BOLD, fontSize=10, textColor=SIGNAL, leading=12),
        "title": ParagraphStyle("title", **{**base, "fontName": SANS_BOLD}, fontSize=22, leading=28),
        "meta": ParagraphStyle("meta", **{**base, "textColor": MUTED}, fontSize=10, leading=14),
        # keepWithNext: a heading (and the line under it) never stays alone at the bottom of a page
        "h1": ParagraphStyle(
            "h1", **{**base, "fontName": SANS_BOLD}, fontSize=14, leading=18, spaceBefore=4, spaceAfter=4, keepWithNext=1
        ),
        "body": ParagraphStyle("body", **base, fontSize=10, leading=14, spaceAfter=4),
        "intro": ParagraphStyle("intro", **base, fontSize=10, leading=14, spaceAfter=4, keepWithNext=1),
        "cell": ParagraphStyle("cell", **base, fontSize=9, leading=12),
        "badge": ParagraphStyle("badge", **base, fontSize=8, leading=10),
        "finding_title": ParagraphStyle("finding_title", **base, fontSize=10.5, leading=13),
        "finding_text": ParagraphStyle("finding_text", **base, fontSize=9.5, leading=13, leftIndent=25 * mm, spaceBefore=2),
        "finding_meta": ParagraphStyle(
            "finding_meta", **{**base, "textColor": MUTED}, fontSize=8, leading=11, leftIndent=25 * mm, spaceBefore=2
        ),
    }
