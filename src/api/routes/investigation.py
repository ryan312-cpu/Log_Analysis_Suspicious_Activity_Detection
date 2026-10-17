from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.routes.alerts import alert_to_response
from src.api.routes.events import event_to_response
from src.api.schemas import InvestigationResponse
from src.api.security.auth import require_authenticated
from src.api.security.input_validator import validate_ip_address
from src.api.services.investigation_service import investigate_source

router = APIRouter(
    prefix="/investigation",
    tags=["Investigation"],
    dependencies=[Depends(require_authenticated)],
)


@router.get("/source/{source_ip}", response_model=InvestigationResponse)
def investigate(
    source_ip: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    source_ip = validate_ip_address(source_ip)
    events, alerts = investigate_source(
        db=db,
        source_ip=source_ip,
        limit=limit,
    )

    return InvestigationResponse(
        source_ip=source_ip,
        events=[event_to_response(event) for event in events],
        alerts=[alert_to_response(alert) for alert in alerts],
    )
