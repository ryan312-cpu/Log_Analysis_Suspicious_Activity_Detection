from pathlib import Path
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(report: Dict[str, Any], output_path: str) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Security Analytics Report", styles["Title"]))
    story.append(Paragraph("Log Analysis & Suspicious Activity Detection", styles["Heading2"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"Generated: {report['report_metadata']['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))

    summary = report["executive_summary"]
    summary_table = Table(
        [
            ["Metric", "Value"],
            ["Total Events", summary["total_events"]],
            ["Total Alerts", summary["total_alerts"]],
            ["Total Incidents", summary["total_incidents"]],
            ["Average Alert Risk", summary["average_alert_risk"]],
        ],
        colWidths=[90 * mm, 60 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 20))
    story.append(Paragraph("Alert Summary", styles["Heading2"]))

    alert_data = [["Alert ID", "Rule", "Severity", "Risk", "Source"]]
    for alert in report["alerts"]:
        alert_data.append(
            [
                str(alert["alert_id"]),
                str(alert["rule_name"]),
                str(alert["severity"]),
                str(alert["risk_score"]),
                str(alert["source_ip"]),
            ]
        )

    if len(alert_data) > 1:
        alert_table = Table(alert_data, repeatRows=1)
        alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(alert_table)

    story.append(Spacer(1, 20))
    story.append(Paragraph("Incident Summary", styles["Heading2"]))

    incident_data = [["Incident ID", "Title", "Severity", "Status"]]
    for incident in report["incidents"]:
        incident_data.append(
            [
                str(incident["incident_id"]),
                str(incident["title"]),
                str(incident["severity"]),
                str(incident["status"]),
            ]
        )

    if len(incident_data) > 1:
        incident_table = Table(incident_data, repeatRows=1)
        incident_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(incident_table)

    story.append(Spacer(1, 20))
    story.append(Paragraph("Top Source IPs", styles["Heading2"]))

    source_data = [["Source IP", "Event Count"]]
    for ip, count in report["event_statistics"]["top_source_ips"].items():
        source_data.append([str(ip), str(count)])

    source_table = Table(source_data, repeatRows=1)
    source_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(source_table)

    document.build(story)
    return output
