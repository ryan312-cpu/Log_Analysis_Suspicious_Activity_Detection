import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas import IncidentNoteCreate, IncidentResponse, IncidentStatusUpdate
from src.api.security.auth import require_admin, require_authenticated
from src.api.security.input_validator import (
    validate_optional_ip,
    validate_optional_string,
    validate_string_input,
)
from src.incidents.lifecycle import allowed_incident_transition, validate_incident_status
from src.storage.models import IncidentModel

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
    dependencies=[Depends(require_authenticated)],
)


def incident_to_response(incident: IncidentModel) -> IncidentResponse:
    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        owner=incident.owner,
        source_ip=incident.source_ip,
        alert_ids=json.loads(incident.alert_ids),
        evidence=json.loads(incident.evidence),
        notes=json.loads(incident.notes),
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        resolved_at=incident.resolved_at.isoformat() if incident.resolved_at else None,
    )


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    severity: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    severity = validate_optional_string(severity, "severity")
    status = validate_optional_string(status, "status")
    source_ip = validate_optional_ip(source_ip)

    query = db.query(IncidentModel)

    if severity:
        query = query.filter(IncidentModel.severity == severity.upper())

    if status:
        query = query.filter(IncidentModel.status == status.upper())

    if source_ip:
        query = query.filter(IncidentModel.source_ip == source_ip)

    incidents = query.order_by(IncidentModel.created_at.desc()).limit(limit).all()

    return [incident_to_response(incident) for incident in incidents]


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident_id = validate_string_input(incident_id, "incident_id")
    incident = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident_to_response(incident)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin),
):
    incident_id = validate_string_input(incident_id, "incident_id")
    incident = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    new_status = validate_string_input(payload.status, "status").upper()

    if not validate_incident_status(new_status):
        raise HTTPException(status_code=400, detail=f"Invalid incident status: {new_status}")

    if incident.status != new_status:
        if not allowed_incident_transition(incident.status, new_status):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid transition: {incident.status} -> {new_status}",
            )

    incident.status = new_status
    if new_status == "RESOLVED":
        incident.resolved_at = incident.updated_at
    db.commit()
    db.refresh(incident)

    return incident_to_response(incident)


@router.post("/{incident_id}/notes", response_model=IncidentResponse)
def add_incident_note(
    incident_id: str,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin),
):
    incident_id = validate_string_input(incident_id, "incident_id")
    incident = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    note = validate_string_input(payload.note, "note")
    if not note:
        raise HTTPException(status_code=400, detail="Note cannot be empty")

    notes = json.loads(incident.notes)
    notes.append(f"[{incident.updated_at.isoformat()}] {note}")
    incident.notes = json.dumps(notes)
    db.commit()
    db.refresh(incident)

    return incident_to_response(incident)
