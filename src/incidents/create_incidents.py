from src.incidents.service import IncidentService
from src.storage.database import get_session
from src.storage.models import AlertModel, IncidentModel


def main():
    db = get_session()
    service = IncidentService()

    try:
        alerts = (
            db.query(AlertModel)
            .filter(AlertModel.status != "FALSE_POSITIVE")
            .all()
        )

        created = 0

        for alert in alerts:
            existing = (
                db.query(IncidentModel)
                .filter(IncidentModel.alert_ids.contains(alert.alert_id))
                .first()
            )

            if existing:
                continue

            service.create_from_alert(db, alert)
            created += 1

        print(f"Created {created} incidents.")

    finally:
        db.close()


if __name__ == "__main__":
    main()
