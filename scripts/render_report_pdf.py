"""Render the authoritative report Markdown with explicit, checked page boundaries.

Uses optional document tooling (ReportLab, Pillow, pypdf) already available in the
authoring environment. It does not affect the analytics runtime requirements.
"""

import argparse
import hashlib
import html
import json
import re
from pathlib import Path


def inline(value):
    """Render the small Markdown subset used by this report; escape source strings."""
    tokens = []

    def keep(value):
        tokens.append(value)
        return f"ZZTOKEN{len(tokens) - 1}ZZ"

    value = re.sub(
        r"`([^`]+)`",
        lambda m: keep(f'<font name="Courier">{html.escape(m[1])}</font>'),
        value,
    )
    value = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: keep(
            f'<link href="{html.escape(m[2], quote=True)}" color="#195878">'
            f"{html.escape(m[1])}</link>"
        ),
        value,
    )
    value = html.escape(value)
    value = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", value)
    for i, token in enumerate(tokens):
        value = value.replace(f"ZZTOKEN{i}ZZ", token)
    return value


def render(source, output):
    from PIL import Image as PILImage
    from pypdf import PdfReader, PdfWriter
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Image, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table

    font_dir = Path("C:/Windows/Fonts")
    for name, filename in [("Report", "arial.ttf"), ("ReportBold", "arialbd.ttf")]:
        pdfmetrics.registerFont(TTFont(name, str(font_dir / filename)))
    pdfmetrics.registerFontFamily("Report", normal="Report", bold="ReportBold", italic="Report")
    body = ParagraphStyle(
        "body",
        fontName="Report",
        fontSize=9.5,
        leading=12.2,
        textColor=colors.HexColor("#162f3a"),
        spaceAfter=7,
        alignment=TA_LEFT,
    )
    styles = {
        1: ParagraphStyle(
            "title", parent=body, fontName="ReportBold", fontSize=21, leading=24, spaceAfter=11
        ),
        2: ParagraphStyle(
            "heading",
            parent=body,
            fontName="ReportBold",
            fontSize=13.5,
            leading=16,
            spaceBefore=7,
            spaceAfter=8,
        ),
        3: ParagraphStyle(
            "figure", parent=body, fontName="ReportBold", fontSize=14, leading=17, spaceAfter=9
        ),
    }
    cell = ParagraphStyle("cell", parent=body, fontSize=8.2, leading=10.5, spaceAfter=0)
    code_style = ParagraphStyle("code", fontName="Courier", fontSize=7.5, leading=9.5, spaceAfter=8)
    parts = re.split(r"<!-- page: (portrait|landscape) -->", source.read_text(encoding="utf-8"))
    pages = list(zip(parts[1::2], parts[2::2], strict=True))
    if not pages:
        raise ValueError("The report must declare at least one page")
    scratch = source.parent.parent / ".local/final/pdf-pages"
    scratch.mkdir(parents=True, exist_ok=True)
    figures = []
    merged = PdfWriter()
    for number, (orientation, markdown) in enumerate(pages, 1):
        size = landscape(A4) if orientation == "landscape" else A4
        width = size[0] - 72
        story = []
        lines = markdown.strip().splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line.startswith("```"):
                code = []
                i += 1
                while i < len(lines) and not lines[i].startswith("```"):
                    code.append(lines[i])
                    i += 1
                story.append(Preformatted("\n".join(code), code_style))
            elif line.startswith("|"):
                rows = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    values = re.split(r"(?<!\\)\|", lines[i].strip().strip("|"))
                    if not all(re.fullmatch(r"[\s:\-]+", v) for v in values):
                        rows.append([Paragraph(inline(v.strip()), cell) for v in values])
                    i += 1
                weights = {
                    2: [0.35, 0.65],
                    3: [0.70, 0.15, 0.15],
                    5: [0.14, 0.20, 0.28, 0.18, 0.20],
                }[len(rows[0])]
                table = Table(rows, colWidths=[width * w for w in weights], hAlign="LEFT")
                table.setStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#deedf2")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#468199")),
                        ("LINEBELOW", (0, 1), (-1, -1), 0.3, colors.HexColor("#ced9df")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
                story.extend([table, Spacer(1, 9)])
                continue
            elif line.startswith("!["):
                match = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", line)
                path = (source.parent / match[2]).resolve()
                # Presentational clipping only. Original PNGs remain untouched.
                crops = {
                    "01-overview.png": (7, 145, 1807, 1073),
                    "final-primary-scenario.png": (7, 162, 1807, 1167),
                    "06-service-create-evidence.png": (7, 382, 1807, 1307),
                }
                crop = crops[path.name]
                with PILImage.open(path) as original:
                    clipped = original.crop(crop)
                    cropped_path = scratch / f"figure-{number}.png"
                    clipped.save(cropped_path)
                    scale = min(width / clipped.width, 418 / clipped.height)
                    story.append(
                        Image(
                            str(cropped_path),
                            width=clipped.width * scale,
                            height=clipped.height * scale,
                        )
                    )
                    figures.append(
                        {
                            "source": path.relative_to(source.parent.parent).as_posix(),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "original_pixels": list(original.size),
                            "crop_box": list(crop),
                            "page": number,
                            "effective_dpi": round(72 / scale),
                        }
                    )
                story.append(Spacer(1, 9))
            elif line.startswith("#"):
                heading = re.match(r"(#{1,3})\s+(.*)", line)
                story.append(Paragraph(inline(heading[2]), styles[len(heading[1])]))
            else:
                paragraph = [line]
                bullet = line.startswith("- ")
                i += 1
                while (
                    i < len(lines)
                    and lines[i].strip()
                    and not lines[i].startswith(("#", "|", "```", "![", "- "))
                ):
                    paragraph.append(lines[i].strip())
                    i += 1
                content = " ".join(paragraph)
                story.append(
                    Paragraph(
                        inline(content[2:] if bullet else content),
                        body,
                        bulletText="•" if bullet else None,
                    )
                )
                continue
            i += 1

        def footer(canvas, doc, page_number=number, page_size=size):
            canvas.setStrokeColor(colors.HexColor("#9bb5c1"))
            canvas.line(36, 31, page_size[0] - 36, 31)
            canvas.setFont("Report", 8)
            canvas.setFillColor(colors.HexColor("#496473"))
            canvas.drawString(36, 20, "ATT&CK detection and correlation · Windows-APT 2025 v4")
            canvas.drawRightString(page_size[0] - 36, 20, f"{page_number} / {len(pages)}")

        page_path = scratch / f"page-{number}.pdf"
        doc = SimpleDocTemplate(
            str(page_path),
            pagesize=size,
            leftMargin=36,
            rightMargin=36,
            topMargin=28,
            bottomMargin=41,
            title="Correlated Detection of MITRE ATT&CK Sub-Techniques",
            author="",
        )
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        single = PdfReader(page_path)
        if len(single.pages) != 1:
            raise ValueError(
                f"Declared page {number} overflowed to {len(single.pages)} pages; revise the report"
            )
        merged.append(single)
    output.parent.mkdir(parents=True, exist_ok=True)
    merged.add_metadata(
        {
            "/Title": "Correlated Detection of MITRE ATT&CK Sub-Techniques",
            "/Subject": "ATT&CK detection and correlation",
            "/Author": "",
        }
    )
    with output.open("wb") as stream:
        merged.write(stream)
    count = len(PdfReader(output).pages)
    audit = {
        "source": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "pdf": output.name,
        "pdf_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "page_count": count,
        "figures": figures,
        "visual_inspection": "pending",
    }
    (source.parent / "report-render-validation.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({"pdf": str(output), "page_count": count, "figures": len(figures)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("reports/technical-report.md"))
    parser.add_argument("--output", type=Path, default=Path("reports/technical-report.pdf"))
    args = parser.parse_args()
    render(args.source.resolve(), args.output.resolve())
