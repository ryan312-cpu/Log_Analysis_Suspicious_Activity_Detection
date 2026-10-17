from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas import EventResponse
from src.api.security.auth import require_authenticated
from src.api.security.input_validator import (
    validate_optional_ip,
    validate_optional_string,
    validate_optional_timestamp,
)
from src.storage.models import EventModel

router = APIRouter(
    prefix="/events",
    tags=["Events"],
    dependencies=[Depends(require_authenticated)],
)


def event_to_response(event: EventModel) -> EventResponse:
    return EventResponse(
        id=event.id,
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        event_category=event.event_category,
        source_ip=event.source_ip,
        source_port=event.source_port,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        username=event.username,
        hostname=event.hostname,
        service=event.service,
        action=event.action,
        status=event.status,
        http_method=event.http_method,
        http_path=event.http_path,
        response_code=event.response_code,
        user_agent=event.user_agent,
        source_type=event.source_type,
        raw_log=event.raw_log,
    )


@router.get("", response_model=list[EventResponse])
def search_events(
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    event_category: Optional[str] = None,
    status: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    source_ip = validate_optional_ip(source_ip)
    username = validate_optional_string(username, "username")
    event_type = validate_optional_string(event_type, "event_type")
    event_category = validate_optional_string(event_category, "event_category")
    status = validate_optional_string(status, "status")
    since = validate_optional_timestamp(since)
    until = validate_optional_timestamp(until)

    query = db.query(EventModel)

    if source_ip:
        query = query.filter(EventModel.source_ip == source_ip)

    if username:
        query = query.filter(EventModel.username == username)

    if event_type:
        query = query.filter(EventModel.event_type == event_type)

    if event_category:
        query = query.filter(EventModel.event_category == event_category)

    if status:
        query = query.filter(EventModel.status == status)

    if since:
        query = query.filter(EventModel.timestamp >= since)

    if until:
        query = query.filter(EventModel.timestamp <= until)

    events = query.order_by(EventModel.timestamp.desc()).limit(limit).all()

    return [event_to_response(event) for event in events]


@router.get("/source/{source_ip}", response_model=list[EventResponse])
def get_events_by_source(
    source_ip: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    source_ip = validate_optional_ip(source_ip)
    events = (
        db.query(EventModel)
        .filter(EventModel.source_ip == source_ip)
        .order_by(EventModel.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [event_to_response(event) for event in events]


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
):
    event_id = validate_optional_string(event_id, "event_id")
    event = db.query(EventModel).filter(EventModel.event_id == event_id).first()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return event_to_response(event)
