import json
from datetime import datetime

from src.storage.models import IncidentModel


class IncidentRepository:
    def create(
        self,
        db,
        incident_id: str,
        title: str,
        description: str,
        severity: str,
        source_ip: str | None,
        alert_ids: list[str],
        evidence: list[str],
        owner: str | None = None,
    ):
        incident = IncidentModel(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status="OPEN",
            owner=owner,
            source_ip=source_ip,
            alert_ids=json.dumps(alert_ids),
            evidence=json.dumps(evidence),
            notes=json.dumps([]),
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    def get_by_id(self, db, incident_id: str):
        return (
            db.query(IncidentModel)
            .filter(IncidentModel.incident_id == incident_id)
            .first()
        )

    def list_incidents(
        self,
        db,
        severity: str | None = None,
        status: str | None = None,
        source_ip: str | None = None,
    ):
        query = db.query(IncidentModel)

        if severity:
            query = query.filter(IncidentModel.severity == severity.upper())

        if status:
            query = query.filter(IncidentModel.status == status.upper())

        if source_ip:
            query = query.filter(IncidentModel.source_ip == source_ip)

        return query.order_by(IncidentModel.created_at.desc()).all()

    def update_status(self, db, incident, new_status: str):
        incident.status = new_status.upper()

        if new_status.upper() == "RESOLVED":
            incident.resolved_at = datetime.utcnow()

        db.commit()
        db.refresh(incident)

        return incident

    def add_note(self, db, incident, note: str):
        notes = json.loads(incident.notes)
        notes.append(note)
        incident.notes = json.dumps(notes)
        db.commit()
        db.refresh(incident)

        return incident
