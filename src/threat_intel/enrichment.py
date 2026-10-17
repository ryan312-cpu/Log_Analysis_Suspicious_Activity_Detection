from src.threat_intel.models import ThreatIntelRecord
from src.threat_intel.service import ThreatIntelService


class ThreatEnrichment:
    def __init__(self, service: ThreatIntelService | None = None):
        self.service = service or ThreatIntelService()

    def enrich(self, ip_address: str) -> float:
        record = self.service.lookup_ip(ip_address)
        return enrich_ip(ip_address, record)

    def score_ip(self, ip_address: str) -> float:
        return self.enrich(ip_address)


def enrich_ip(ip_address: str, record: ThreatIntelRecord | None) -> float:
    if record is None:
        return 0.0

    confidence_bonus = float(record.confidence) * 0.2
    return min(confidence_bonus, 20.0)
