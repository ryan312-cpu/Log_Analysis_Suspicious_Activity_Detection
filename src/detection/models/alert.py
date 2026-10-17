from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str

    severity: str
    title: str
    reason: str

    timestamp: str

    source_ip: Optional[str] = None
    username: Optional[str] = None

    event_ids: List[str] = field(
        default_factory=list
    )

    evidence: List[str] = field(
        default_factory=list
    )

    status: str = "new"
