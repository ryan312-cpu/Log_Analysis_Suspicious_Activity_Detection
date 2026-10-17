from dataclasses import dataclass


@dataclass
class ThreatIntelRecord:
    ip_address: str
    threat_type: str
    confidence: int
    source: str
    description: str
