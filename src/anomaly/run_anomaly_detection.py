from datetime import datetime

from src.anomaly.baseline import build_source_ip_baseline
from src.anomaly.detector import detect_source_volume_anomalies
from src.anomaly.login_behavior import detect_unusual_login_hours
from src.storage.database import get_session
from src.storage.models import EventModel


def load_events():
    db = get_session()

    try:
        return (
            db.query(EventModel)
            .order_by(EventModel.timestamp.asc())
            .all()
        )
    finally:
        db.close()


def split_events(events):

    if not events:
        return [], []

    timestamps = [
        datetime.fromisoformat(event.timestamp)
        for event in events
    ]

    cutoff = (
        min(timestamps)
        + (max(timestamps) - min(timestamps)) / 2
    )

    historical = []
    current = []

    for event in events:
        timestamp = datetime.fromisoformat(event.timestamp)

        if timestamp <= cutoff:
            historical.append(event)
        else:
            current.append(event)

    return historical, current


def main():

    events = load_events()

    print(f"Loaded {len(events)} events.")

    historical, current = split_events(events)

    print(f"Historical events: {len(historical)}")
    print(f"Current events: {len(current)}")

    baseline = build_source_ip_baseline(historical)

    print(f"Baselines created: {len(baseline)}")

    findings = detect_source_volume_anomalies(current, baseline)
    login_findings = detect_unusual_login_hours(events)
    findings.extend(login_findings)

    print(f"\nAnomalies detected: {len(findings)}")

    for finding in findings:
        print("\n" + "=" * 60)
        print(f"Anomaly ID : {finding.anomaly_id}")
        print(f"Type       : {finding.anomaly_type}")
        print(f"Severity   : {finding.severity}")
        print(f"Score      : {finding.score}")
        print(f"Source IP  : {finding.source_ip}")
        print(f"Reason     : {finding.reason}")
        print("Evidence:")

        for evidence in finding.evidence:
            print(f"  - {evidence}")


if __name__ == "__main__":
    main()
