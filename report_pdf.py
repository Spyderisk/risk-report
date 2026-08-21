import csv
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A3, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

from report_profile import project_rows


def _read_csv(csv_path):
    with Path(csv_path).open(newline="", encoding="utf-8-sig") as csv_file:
        return list(csv.reader(csv_file))


def _column_widths(rows, available_width):
    column_count = max((len(row) for row in rows), default=1)
    weights = []
    for column_index in range(column_count):
        longest = max(
            (len(row[column_index]) for row in rows if column_index < len(row)),
            default=1,
        )
        weights.append(min(max(longest, 8), 45))
    total_weight = sum(weights) or 1
    return [available_width * weight / total_weight for weight in weights]


def _table(rows, available_width):
    cell_style = ParagraphStyle(
        "ReportCell",
        fontName="Helvetica",
        fontSize=5.5,
        leading=6.5,
        alignment=TA_LEFT,
        spaceAfter=0,
        spaceBefore=0,
    )
    header_style = ParagraphStyle(
        "ReportHeader",
        parent=cell_style,
        fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    column_count = max((len(row) for row in rows), default=1)
    normalized_rows = [row + [""] * (column_count - len(row)) for row in rows]
    table_data = []
    for row_index, row in enumerate(normalized_rows):
        style = header_style if row_index == 0 else cell_style
        table_data.append([Paragraph(escape(value or ""), style) for value in row])

    table = LongTable(
        table_data,
        colWidths=_column_widths(normalized_rows, available_width),
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24445c")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#8a99a5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f4f6")]),
    ]))
    return table


def render_report_pdf(sections, output_path, iso_standard):
    """Render configured views of named CSV report sections into one PDF."""
    output_path = Path(output_path)
    page_width, _ = landscape(A3)
    margin = 12 * mm
    available_width = page_width - (2 * margin)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=19,
        textColor=colors.HexColor("#17364d"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#405665"),
    )

    story = []
    for section_index, (section_name, csv_path) in enumerate(sections):
        rows, _ = project_rows(_read_csv(csv_path), section_name, iso_standard)
        if section_index:
            story.append(PageBreak())
        story.append(Paragraph(f"{escape(section_name)} report", title_style))
        if section_name.lower() == "security":
            story.append(Paragraph(f"ISO standard: {escape(iso_standard)}", subtitle_style))
        story.append(Spacer(1, 5 * mm))
        if rows:
            story.append(_table(rows, available_width))
        else:
            story.append(Paragraph("No report rows were generated.", styles["Normal"]))

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=landscape(A3),
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
        title="Spyderisk report",
        author="Spyderisk",
    )
    document.build(story)
    return output_path
