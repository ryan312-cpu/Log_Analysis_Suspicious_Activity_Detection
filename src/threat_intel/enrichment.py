from dataclasses import dataclass

from src.threat_intel.models import ThreatIntelRecord
from src.threat_intel.service import ThreatIntelService


@dataclass
class EnrichmentResult:
    """Result of a threat-intelligence enrichment lookup."""

    ip_address: str
    matched: bool
    risk_bonus: float
    threat_type: str | None = None
    confidence: int | None = None
    source: str | None = None


class ThreatEnrichment:
    def __init__(self, service: ThreatIntelService | None = None):
        self.service = service or ThreatIntelService()

    def enrich(self, ip_address: str) -> EnrichmentResult:
        record = self.service.lookup_ip(ip_address)
        return enrich_ip(ip_address, record)

    def score_ip(self, ip_address: str) -> float:
        return self.enrich(ip_address).risk_bonus


def enrich_ip(ip_address: str, record: ThreatIntelRecord | None) -> EnrichmentResult:
    """Return an EnrichmentResult for *ip_address*.

    risk_bonus is ``confidence * 0.2`` capped at 20.0.  When *record* is
    ``None`` the IP is unknown and risk_bonus is 0.0.
    """
    if record is None:
        return EnrichmentResult(ip_address=ip_address, matched=False, risk_bonus=0.0)

    confidence_bonus = float(record.confidence) * 0.2
    risk_bonus = min(confidence_bonus, 20.0)

    return EnrichmentResult(
        ip_address=ip_address,
        matched=True,
        risk_bonus=risk_bonus,
        threat_type=record.threat_type,
        confidence=record.confidence,
        source=record.source,
    )
