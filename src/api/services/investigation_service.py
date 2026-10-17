from sqlalchemy.orm import Session

from src.storage.models import AlertModel, EventModel


def investigate_source(
    db: Session,
    source_ip: str,
    limit: int = 100,
):
    events = (
        db.query(EventModel)
        .filter(EventModel.source_ip == source_ip)
        .order_by(EventModel.timestamp.desc())
        .limit(limit)
        .all()
    )

    alerts = (
        db.query(AlertModel)
        .filter(AlertModel.source_ip == source_ip)
        .order_by(AlertModel.created_at.desc())
        .limit(limit)
        .all()
    )

    return events, alerts
