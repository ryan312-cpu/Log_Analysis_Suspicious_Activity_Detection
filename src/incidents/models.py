from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Incident:
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    owner: Optional[str] = None
    source_ip: Optional[str] = None
    alert_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None
