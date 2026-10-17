import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.detection.models.alert import Alert
from src.storage.models import AlertModel


class AlertRepository:

    def __init__(self, session: Session):
        self.session = session

    def save_alert(
        self,
        alert: Alert,
        risk_score: float,
    ) -> AlertModel:

        existing = self.session.scalar(
            select(AlertModel).where(
                AlertModel.alert_id == alert.alert_id
            )
        )

        if existing:
            return existing

        record = AlertModel(
            alert_id=alert.alert_id,
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            risk_score=risk_score,
            title=alert.title,
            reason=alert.reason,
            timestamp=alert.timestamp,
            source_ip=alert.source_ip,
            username=alert.username,
            status="NEW",
            event_ids=json.dumps(alert.event_ids),
            evidence=json.dumps(alert.evidence),
        )

        self.session.add(record)

        return record

    def save_alerts(
        self,
        alerts,
        risk_scores,
    ) -> int:

        inserted = 0

        for alert in alerts:
            existing = self.session.scalar(
                select(AlertModel).where(
                    AlertModel.alert_id == alert.alert_id
                )
            )

            if existing:
                continue

            self.save_alert(
                alert,
                risk_scores[alert.alert_id],
            )
            inserted += 1

        self.session.commit()
        return inserted

    def count_alerts(self) -> int:

        return (
            self.session.scalar(
                select(func.count(AlertModel.id))
            )
            or 0
        )

    def get_new_alerts(self):

        return list(
            self.session.scalars(
                select(AlertModel)
                .where(
                    AlertModel.status == "NEW"
                )
                .order_by(
                    AlertModel.risk_score.desc()
                )
            )
        )

    def get_by_severity(
        self,
        severity: str,
    ):

        return list(
            self.session.scalars(
                select(AlertModel)
                .where(
                    AlertModel.severity == severity
                )
                .order_by(
                    AlertModel.timestamp.desc()
                )
            )
        )

    def update_status(
        self,
        alert_id: str,
        new_status: str,
    ):

        from src.detection.alert_lifecycle import (
            allowed_transition,
            validate_status,
        )

        new_status = new_status.upper()

        if not validate_status(new_status):
            raise ValueError(
                f"Invalid alert status: {new_status}"
            )

        alert = self.session.scalar(
            select(AlertModel).where(
                AlertModel.alert_id == alert_id
            )
        )

        if alert is None:
            raise ValueError(
                f"Alert not found: {alert_id}"
            )

        if not allowed_transition(
            alert.status,
            new_status,
        ):
            raise ValueError(
                f"Invalid transition: {alert.status} -> {new_status}"
            )

        alert.status = new_status
        self.session.commit()
        return alert
