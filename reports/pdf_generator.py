"""
PDF Report Generator

Generates PDF vulnerability reports using reportlab.
The PDF includes:
- Cover page with scan metadata
- Executive summary with severity breakdown
- Detailed vulnerability listings with fix suggestions
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# Severity colour map (ReportLab HexColor strings)
_SEVERITY_COLORS = {
    "Critical": "#dc3545",
    "High":     "#fd7e14",
    "Medium":   "#ffc107",
    "Low":      "#17a2b8",
    "Info":     "#6c757d",
}

_DEFAULT_SEVERITY_COLOR = "#6c757d"


def generate_pdf_report(
    output_path: str,
    target_url: str,
    vulnerabilities: List[Dict],
    urls_crawled: int = 0,
    forms_found: int = 0,
    scan_duration: str = "",
    modules_used: List[str] = None,
) -> str:
    """
    Generate a PDF vulnerability report.

    Args:
        output_path:     Destination file path (e.g. "scan_report.pdf")
        target_url:      Target URL that was scanned
        vulnerabilities: List of vulnerability dicts from the scanner
        urls_crawled:    Number of URLs crawled
        forms_found:     Number of forms discovered
        scan_duration:   Human-readable scan duration string
        modules_used:    List of scanner module names

    Returns:
        Absolute path to the generated PDF file.

    Raises:
        ImportError: When reportlab is not installed.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF generation. "
            "Install it with: pip install reportlab"
        )

    modules_used = modules_used or []
    report_time = datetime.now()

    # ------------------------------------------------------------------ #
    # Severity summary
    # ------------------------------------------------------------------ #
    severity_stats: Dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }
    for v in vulnerabilities:
        sev = v.get("severity", "Info")
        severity_stats[sev] = severity_stats.get(sev, 0) + 1

    # ------------------------------------------------------------------ #
    # Document setup
    # ------------------------------------------------------------------ #
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_file),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Vulnerability Scan Report – {target_url}",
        author="Web Vulnerability Scanner",
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        textColor=colors.HexColor("#4a4a6a"),
        spaceAfter=2,
        alignment=TA_CENTER,
    )
    section_heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=4,
    )
    vuln_type_style = ParagraphStyle(
        "VulnType",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#333333"),
        alignment=TA_JUSTIFY,
    )
    label_style = ParagraphStyle(
        "Label",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#555555"),
        fontName="Helvetica-Bold",
    )
    code_style = ParagraphStyle(
        "Code",
        parent=styles["Code"],
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#222222"),
        backColor=colors.HexColor("#f4f4f4"),
        borderPad=4,
    )
    recommendation_style = ParagraphStyle(
        "Recommendation",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1b5e20"),
        backColor=colors.HexColor("#e8f5e9"),
        borderPad=6,
        alignment=TA_JUSTIFY,
    )

    story: List[Any] = []

    # ------------------------------------------------------------------ #
    # Cover page
    # ------------------------------------------------------------------ #
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("🔒 Vulnerability Scan Report", title_style))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"<b>Target:</b> {target_url}", subtitle_style))
    story.append(Paragraph(
        f"Generated: {report_time.strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style,
    ))
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#667eea")))
    story.append(Spacer(1, 0.6 * cm))

    # Summary table
    summary_data = [
        ["URLs Crawled", "Forms Found", "Vulnerabilities", "Modules"],
        [
            str(urls_crawled),
            str(forms_found),
            str(len(vulnerabilities)),
            str(len(modules_used)),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[4 * cm] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 1 * cm))

    # Severity breakdown table
    story.append(Paragraph("Severity Breakdown", section_heading_style))
    sev_data = [["Severity", "Count"]]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        sev_data.append([sev, str(severity_stats.get(sev, 0))])

    sev_table = Table(sev_data, colWidths=[8 * cm, 8 * cm])
    sev_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    row_color_map = {
        1: "#dc3545", 2: "#fd7e14", 3: "#ffc107", 4: "#17a2b8", 5: "#6c757d"
    }
    for row_idx, hex_color in row_color_map.items():
        sev_style_cmds.append(
            ("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor(hex_color))
        )
        text_color = colors.HexColor("#333333") if hex_color == "#ffc107" else colors.white
        sev_style_cmds.append(
            ("TEXTCOLOR", (0, row_idx), (-1, row_idx), text_color)
        )
    sev_table.setStyle(TableStyle(sev_style_cmds))
    story.append(sev_table)

    # Scan details
    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph("Scan Details", section_heading_style))
    details_data = [
        ["Scan Time", report_time.strftime("%Y-%m-%d %H:%M:%S")],
        ["Duration", scan_duration or "N/A"],
        ["Modules Used", ", ".join(modules_used) if modules_used else "N/A"],
    ]
    details_table = Table(details_data, colWidths=[5 * cm, 11 * cm])
    details_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(details_table)

    # ------------------------------------------------------------------ #
    # Vulnerability details
    # ------------------------------------------------------------------ #
    story.append(PageBreak())
    story.append(Paragraph("Vulnerability Details", section_heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))

    if not vulnerabilities:
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            "✅  No vulnerabilities were detected during this scan.",
            ParagraphStyle(
                "NoVulns",
                parent=styles["Normal"],
                fontSize=12,
                textColor=colors.HexColor("#28a745"),
                alignment=TA_CENTER,
            ),
        ))
    else:
        # Group by vulnerability type
        by_type: Dict[str, List[Dict]] = {}
        for v in vulnerabilities:
            vtype = v.get("type", "Unknown")
            by_type.setdefault(vtype, []).append(v)

        for vtype, vulns in by_type.items():
            story.append(Paragraph(f"{vtype} ({len(vulns)})", vuln_type_style))

            for idx, vuln in enumerate(vulns, start=1):
                sev = vuln.get("severity", "Info")
                sev_color = _SEVERITY_COLORS.get(sev, _DEFAULT_SEVERITY_COLOR)

                # Severity badge row
                badge_data = [[
                    Paragraph(f"<b>#{idx}</b>", label_style),
                    Paragraph(
                        f'<font color="{sev_color}"><b>{sev}</b></font>',
                        label_style,
                    ),
                ]]
                badge_table = Table(badge_data, colWidths=[2 * cm, 14 * cm])
                badge_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(sev_color)),
                ]))
                story.append(badge_table)

                # Detail table
                detail_rows = [
                    ["URL", vuln.get("url", "N/A")],
                    ["Parameter", vuln.get("parameter", "N/A")],
                    ["Payload", vuln.get("payload", "N/A")[:120]],
                    ["Evidence", (vuln.get("evidence") or "N/A")[:200]],
                ]
                detail_table = Table(
                    [[Paragraph(k, label_style), Paragraph(v, code_style)]
                     for k, v in detail_rows],
                    colWidths=[3 * cm, 13 * cm],
                )
                detail_table.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(detail_table)

                # Description
                if vuln.get("description"):
                    story.append(Spacer(1, 0.2 * cm))
                    story.append(Paragraph(
                        f"<b>Description:</b> {vuln['description']}",
                        body_style,
                    ))

                # Recommendation
                if vuln.get("recommendation"):
                    story.append(Spacer(1, 0.2 * cm))
                    story.append(Paragraph(
                        f"<b>✅ Recommendation:</b> {vuln['recommendation']}",
                        recommendation_style,
                    ))

                story.append(Spacer(1, 0.5 * cm))

    # ------------------------------------------------------------------ #
    # Footer disclaimer
    # ------------------------------------------------------------------ #
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Generated by Web Vulnerability Scanner v1.0  •  "
        "This report is for authorized security testing only.",
        ParagraphStyle(
            "Footer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#888888"),
            alignment=TA_CENTER,
        ),
    ))

    doc.build(story)
    return str(output_file)
