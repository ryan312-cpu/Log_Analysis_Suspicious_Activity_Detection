from typing import Optional

from pydantic import BaseModel


class EventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: str

    event_type: str
    event_category: str

    source_ip: Optional[str] = None
    source_port: Optional[int] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    username: Optional[str] = None
    hostname: Optional[str] = None
    service: Optional[str] = None

    action: Optional[str] = None
    status: Optional[str] = None

    http_method: Optional[str] = None
    http_path: Optional[str] = None
    response_code: Optional[int] = None

    user_agent: Optional[str] = None

    source_type: Optional[str] = None
    raw_log: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    alert_id: str

    rule_id: str
    rule_name: str

    severity: str
    risk_score: float

    title: str
    reason: str

    timestamp: str

    source_ip: Optional[str] = None
    username: Optional[str] = None

    status: str

    event_ids: list[str]
    evidence: list[str]

    created_at: str


class AlertStatusUpdate(BaseModel):
    status: str


class ThreatIntelResponse(BaseModel):
    id: int
    ip_address: str
    threat_type: str
    confidence: int
    source: str
    description: str
    created_at: str


class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    owner: Optional[str] = None
    source_ip: Optional[str] = None
    alert_ids: list[str]
    evidence: list[str]
    notes: list[str]
    created_at: str
    updated_at: str
    resolved_at: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: str


class IncidentNoteCreate(BaseModel):
    note: str


class InvestigationResponse(BaseModel):
    source_ip: str
    events: list[EventResponse]
    alerts: list[AlertResponse]
