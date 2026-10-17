import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas import AlertResponse, AlertStatusUpdate
from src.api.security.auth import require_admin, require_authenticated
from src.api.security.input_validator import (
    validate_optional_ip,
    validate_optional_string,
    validate_string_input,
)
from src.detection.alert_lifecycle import allowed_transition, validate_status
from src.storage.models import AlertModel

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
    dependencies=[Depends(require_authenticated)],
)


def alert_to_response(alert: AlertModel) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        alert_id=alert.alert_id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        risk_score=alert.risk_score,
        title=alert.title,
        reason=alert.reason,
        timestamp=alert.timestamp,
        source_ip=alert.source_ip,
        username=alert.username,
        status=alert.status,
        event_ids=json.loads(alert.event_ids),
        evidence=json.loads(alert.evidence),
        created_at=alert.created_at.isoformat(),
    )


@router.get("", response_model=list[AlertResponse])
def search_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    severity = validate_optional_string(severity, "severity")
    status = validate_optional_string(status, "status")
    rule_id = validate_optional_string(rule_id, "rule_id")
    source_ip = validate_optional_ip(source_ip)

    query = db.query(AlertModel)

    if severity:
        query = query.filter(AlertModel.severity == severity.upper())

    if status:
        query = query.filter(AlertModel.status == status.upper())

    if rule_id:
        query = query.filter(AlertModel.rule_id == rule_id)

    if source_ip:
        query = query.filter(AlertModel.source_ip == source_ip)

    alerts = query.order_by(AlertModel.created_at.desc()).limit(limit).all()

    return [alert_to_response(alert) for alert in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
):
    alert_id = validate_string_input(alert_id, "alert_id")
    alert = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert_to_response(alert)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin),
):
    alert_id = validate_string_input(alert_id, "alert_id")
    alert = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    new_status = validate_string_input(payload.status, "status").upper()

    if not validate_status(new_status):
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")

    current_status = alert.status.upper()

    if current_status != new_status:
        if not allowed_transition(current_status, new_status):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid transition: {current_status} -> {new_status}",
            )

    alert.status = new_status
    db.commit()
    db.refresh(alert)

    return alert_to_response(alert)
