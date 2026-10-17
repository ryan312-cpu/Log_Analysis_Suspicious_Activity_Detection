from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas import ThreatIntelResponse
from src.api.security.auth import require_authenticated
from src.api.security.input_validator import (
    validate_ip_address,
    validate_optional_ip,
    validate_optional_string,
)
from src.storage.models import ThreatIntelModel

router = APIRouter(
    prefix="/threat-intel",
    tags=["Threat Intel"],
    dependencies=[Depends(require_authenticated)],
)


def threat_intel_to_response(record: ThreatIntelModel) -> ThreatIntelResponse:
    return ThreatIntelResponse(
        id=record.id,
        ip_address=record.ip_address,
        threat_type=record.threat_type,
        confidence=record.confidence,
        source=record.source,
        description=record.description,
        created_at=record.created_at.isoformat(),
    )


@router.get("", response_model=list[ThreatIntelResponse])
def list_threat_intel(
    threat_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    threat_type = validate_optional_string(threat_type, "threat_type")
    ip_address = validate_optional_ip(ip_address)

    query = db.query(ThreatIntelModel)

    if threat_type:
        query = query.filter(ThreatIntelModel.threat_type == threat_type.lower())

    if ip_address:
        query = query.filter(ThreatIntelModel.ip_address == ip_address)

    records = query.order_by(ThreatIntelModel.created_at.desc()).limit(limit).all()
    return [threat_intel_to_response(record) for record in records]


@router.get("/lookup/{ip_address}", response_model=ThreatIntelResponse)
def lookup_threat_intel(
    ip_address: str,
    db: Session = Depends(get_db),
):
    ip_address = validate_ip_address(ip_address)
    record = (
        db.query(ThreatIntelModel)
        .filter(ThreatIntelModel.ip_address == ip_address)
        .first()
    )

    if record is None:
        raise HTTPException(status_code=404, detail="Threat intel record not found")

    return threat_intel_to_response(record)
