from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AnomalyFinding:
    anomaly_id: str

    anomaly_type: str
    severity: str
    score: float

    timestamp: str

    source_ip: Optional[str] = None
    username: Optional[str] = None

    reason: str = ""

    evidence: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
