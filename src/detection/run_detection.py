from src.detection.alert_processor import process_alert
from src.detection.engine.rule_engine import DetectionEngine
from src.detection.rules.rule_registry import get_rule_library
from src.storage.alert_repository import AlertRepository
from src.storage.database import get_session, initialize_database
from src.storage.models import EventModel


def load_events():

    session = get_session()

    try:
        return list(
            session.query(EventModel)
            .order_by(EventModel.timestamp)
            .all()
        )
    finally:
        session.close()


def build_detection_engine() -> DetectionEngine:
    return DetectionEngine(get_rule_library())


def main():

    print("=" * 70)
    print("SECURITY DETECTION ENGINE")
    print("=" * 70)

    initialize_database()

    events = load_events()

    print(
        f"Events loaded: {len(events)}"
    )

    engine = build_detection_engine()

    alerts = engine.run(events)

    print()
    print(
        f"Alerts generated: {len(alerts)}"
    )

    print("=" * 70)

    session = get_session()

    try:
        alert_repository = AlertRepository(session)
        risk_scores = {}

        for alert in alerts:
            processed = process_alert(alert)
            risk_scores[alert.alert_id] = processed["risk_score"]

            print()
            print(
                f"[{alert.severity}] "
                f"{alert.rule_id} - "
                f"{alert.rule_name}"
            )

            print(
                f"Title: {alert.title}"
            )

            print(
                f"Risk Score: {processed['risk_score']}"
            )

            print(
                f"Reason: {alert.reason}"
            )

            if alert.source_ip:
                print(
                    f"Source IP: "
                    f"{alert.source_ip}"
                )

            if alert.username:
                print(
                    f"Username: "
                    f"{alert.username}"
                )

            print(
                f"Evidence: "
                f"{'; '.join(alert.evidence)}"
            )

            print(
                f"Events: "
                f"{len(alert.event_ids)}"
            )

            print("-" * 70)

        inserted = alert_repository.save_alerts(
            alerts,
            risk_scores,
        )

        print()
        print(f"New alerts stored: {inserted}")
        print(
            f"Total alerts in database: "
            f"{alert_repository.count_alerts()}"
        )
    finally:
        session.close()


if __name__ == "__main__":
    main()
