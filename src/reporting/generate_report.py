import json
from pathlib import Path

from src.storage.database import get_session, initialize_database
from src.storage.models import AlertModel, EventModel, IncidentModel
from src.reporting.report_builder import build_report
from src.reporting.html_report import generate_html_report
from src.reporting.pdf_report import generate_pdf_report

OUTPUT_DIR = Path("reports/generated")


def main():
    initialize_database()
    session = get_session()

    try:
        events = session.query(EventModel).order_by(EventModel.timestamp.asc()).all()
        alerts = session.query(AlertModel).order_by(AlertModel.created_at.desc()).all()
        incidents = session.query(IncidentModel).order_by(IncidentModel.created_at.desc()).all()

        report = build_report(events=events, alerts=alerts, incidents=incidents)

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        json_path = OUTPUT_DIR / "security_report.json"
        html_path = OUTPUT_DIR / "security_report.html"
        pdf_path = OUTPUT_DIR / "security_report.pdf"

        json_path.write_text(json.dumps(report, indent=4, default=str), encoding="utf-8")
        generate_html_report(report, str(html_path))
        generate_pdf_report(report, str(pdf_path))

        print("Security report generated successfully.")
        print(f"JSON : {json_path}")
        print(f"HTML : {html_path}")
        print(f"PDF  : {pdf_path}")
        print(f"Events    : {len(events)}")
        print(f"Alerts    : {len(alerts)}")
        print(f"Incidents : {len(incidents)}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
