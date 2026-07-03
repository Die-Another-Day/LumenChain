"""
LUMENCHAIN — Report Generator
Exports an investigation case to PDF, HTML, JSON, and CSV.
Every value in these reports is pulled directly from the database —
nothing here is templated placeholder text presented as findings.
"""

import json
import csv
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

from ai_detection import build_narrative


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def gather_case_report_data(db, hashchain, case_id: str) -> dict:
    case = db.get_case(case_id)
    logs = db.get_logs(case_id)
    alerts = db.get_alerts(case_id)
    integrity = hashchain.verify_chain(case_id)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1

    narrative = build_narrative(case["name"] if case else case_id, alerts)

    timeline = sorted(
        [{"time": _fmt_ts(a["event_time"]), "raw_time": a["event_time"],
          "severity": a["severity"], "category": a["category"],
          "technique": a["technique"], "description": a["description"],
          "confidence": a["confidence"]} for a in alerts],
        key=lambda x: x["raw_time"],
    )

    return {
        "case": case,
        "generated_at": _fmt_ts(datetime.now().timestamp()),
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "integrity": integrity,
        "narrative": narrative,
        "timeline": timeline,
        "logs": logs,
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def export_json(data: dict) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV (timeline of alerts — the most analyst-actionable flat view)
# ---------------------------------------------------------------------------

def export_csv(data: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["time", "severity", "category", "technique", "confidence", "description"])
    for row in data["timeline"]:
        writer.writerow([row["time"], row["severity"], row["category"],
                          row["technique"], row["confidence"], row["description"]])
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#65a30d"}


def export_html(data: dict) -> bytes:
    case = data["case"] or {}
    integrity = data["integrity"]
    badge_color = "#16a34a" if integrity["valid"] else "#dc2626"
    badge_text = "VERIFIED — NO TAMPERING DETECTED" if integrity["valid"] else "INTEGRITY BREACH DETECTED"

    rows_html = ""
    for row in data["timeline"]:
        c = SEVERITY_COLORS.get(row["severity"], "#666")
        rows_html += f"""
        <tr>
          <td style="white-space:nowrap">{row['time']}</td>
          <td><span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{row['severity'].upper()}</span></td>
          <td>{row['category']}</td>
          <td>{row['technique']}</td>
          <td>{row['description']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>LUMENCHAIN Investigation Report — {case.get('name','Case')}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 40px auto; color:#1a1a1a; line-height:1.5; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  .sub {{ color: #666; margin-bottom: 24px; }}
  .badge {{ display:inline-block; background:{badge_color}; color:white; padding:6px 14px; border-radius:6px; font-weight:600; font-size:13px; }}
  .stats {{ display:flex; gap:16px; margin: 20px 0; }}
  .stat {{ border:1px solid #e5e5e5; border-radius:8px; padding:12px 20px; }}
  .stat .n {{ font-size:22px; font-weight:700; }}
  .stat .l {{ font-size:12px; color:#666; }}
  table {{ width:100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #eee; font-size:13px; }}
  th {{ background:#fafafa; font-size:12px; text-transform:uppercase; color:#666; }}
  .narrative {{ background:#f8f9fa; border-left:3px solid #444; padding:14px 18px; white-space:pre-wrap; font-size:14px; }}
  footer {{ margin-top:40px; font-size:11px; color:#999; }}
</style></head>
<body>
  <h1>LUMENCHAIN Investigation Report</h1>
  <div class="sub">Case: {case.get('name','Unknown')} &nbsp;|&nbsp; ID: {case.get('case_id','')} &nbsp;|&nbsp; Generated: {data['generated_at']}</div>

  <span class="badge">{badge_text}</span>
  <p style="font-size:13px;color:#555">{integrity['details']} ({integrity['blocks_checked']} ledger blocks checked)</p>

  <div class="stats">
    <div class="stat"><div class="n">{data['total_logs']}</div><div class="l">LOGS INGESTED</div></div>
    <div class="stat"><div class="n">{data['total_alerts']}</div><div class="l">DETECTIONS</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLORS['critical']}">{data['severity_counts'].get('critical',0)}</div><div class="l">CRITICAL</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLORS['high']}">{data['severity_counts'].get('high',0)}</div><div class="l">HIGH</div></div>
  </div>

  <h2>Summary</h2>
  <div class="narrative">{data['narrative']}</div>

  <h2>Timeline</h2>
  <table>
    <tr><th>Time</th><th>Severity</th><th>Category</th><th>Technique</th><th>Description</th></tr>
    {rows_html}
  </table>

  <footer>Generated by LUMENCHAIN. Evidence integrity is anchored via SHA-256 hash-chain (see integrity section) — not a public distributed blockchain unless externally anchored. This report reflects only detections produced by the platform's configured rules and models; it is not a substitute for analyst review.</footer>
</body></html>"""
    return html.encode("utf-8")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def export_pdf(data: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, textColor=colors.grey)

    case = data["case"] or {}
    integrity = data["integrity"]

    elements = []
    elements.append(Paragraph("LUMENCHAIN Investigation Report", title_style))
    elements.append(Paragraph(
        f"Case: {case.get('name','Unknown')} &nbsp;|&nbsp; ID: {case.get('case_id','')}<br/>"
        f"Generated: {data['generated_at']}", small))
    elements.append(Spacer(1, 10))

    badge_color = colors.HexColor("#16a34a") if integrity["valid"] else colors.HexColor("#dc2626")
    badge_text = "VERIFIED — NO TAMPERING DETECTED" if integrity["valid"] else "INTEGRITY BREACH DETECTED"
    t = Table([[badge_text]], colWidths=[300])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(t)
    elements.append(Paragraph(f"{integrity['details']} ({integrity['blocks_checked']} ledger blocks checked)", small))
    elements.append(Spacer(1, 10))

    stats_data = [["Logs Ingested", "Detections", "Critical", "High"],
                   [str(data["total_logs"]), str(data["total_alerts"]),
                    str(data["severity_counts"].get("critical", 0)),
                    str(data["severity_counts"].get("high", 0))]]
    st = Table(stats_data, colWidths=[110, 110, 90, 90])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    elements.append(st)

    elements.append(Paragraph("Summary", h2))
    for line in data["narrative"].split("\n"):
        if line.strip():
            elements.append(Paragraph(line.replace("<", "&lt;").replace(">", "&gt;"), body))

    elements.append(Paragraph("Timeline of Detections", h2))
    table_data = [["Time", "Severity", "Category", "Technique", "Description"]]
    for row in data["timeline"]:
        short_time = row["time"].split(" ")[-1] if " " in row["time"] else row["time"]
        table_data.append([
            Paragraph(short_time, small), Paragraph(row["severity"].upper(), small),
            Paragraph(row["category"], small),
            Paragraph(row["technique"], small),
            Paragraph(row["description"], small),
        ])
    if len(table_data) > 1:
        tt = Table(table_data, colWidths=[48, 58, 68, 100, 196], repeatRows=1)
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]))
        elements.append(tt)
    else:
        elements.append(Paragraph("No detections recorded for this case.", body))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph(
        "Generated by LUMENCHAIN. Evidence integrity is anchored via a SHA-256 hash-chain "
        "(see integrity section above) — this is a tamper-evident ledger, not a public "
        "distributed blockchain unless externally anchored. This report reflects only "
        "detections produced by the platform's configured rules and models; it is not a "
        "substitute for analyst review.", small))

    doc.build(elements)
    return buf.getvalue()


def export_report(db, hashchain, case_id: str, fmt: str) -> tuple:
    """Returns (bytes, mime_type, filename)."""
    data = gather_case_report_data(db, hashchain, case_id)
    fmt = fmt.lower()
    if fmt == "json":
        return export_json(data), "application/json", f"{case_id}_report.json"
    if fmt == "csv":
        return export_csv(data), "text/csv", f"{case_id}_report.csv"
    if fmt == "html":
        return export_html(data), "text/html", f"{case_id}_report.html"
    if fmt == "pdf":
        return export_pdf(data), "application/pdf", f"{case_id}_report.pdf"
    raise ValueError(f"Unsupported format: {fmt}")
