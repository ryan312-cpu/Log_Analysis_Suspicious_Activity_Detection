import json
from datetime import datetime
from uuid import uuid4

from src.storage.incident_repository import IncidentRepository


class IncidentService:
    def __init__(self):
        self.repository = IncidentRepository()

    def create_from_alert(self, db, alert):
        incident_id = f"INC-{uuid4().hex[:12]}"
        title = f"Security Incident: {alert.rule_name}"
        description = (
            f"Incident created from alert {alert.alert_id}. {alert.reason}"
        )
        evidence = json.loads(alert.evidence)

        return self.repository.create(
            db=db,
            incident_id=incident_id,
            title=title,
            description=description,
            severity=alert.severity,
            source_ip=alert.source_ip,
            alert_ids=[alert.alert_id],
            evidence=evidence,
        )

    def add_note(self, db, incident, note):
        timestamp = datetime.utcnow().isoformat()
        formatted_note = f"[{timestamp}] {note}"
        return self.repository.add_note(db, incident, formatted_note)
