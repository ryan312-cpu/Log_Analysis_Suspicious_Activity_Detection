from pathlib import Path

from src.threat_intel.feed_loader import load_threat_feed
from src.threat_intel.models import ThreatIntelRecord


class ThreatIntelService:
    """Thin wrapper around a loaded threat-intelligence feed dictionary.

    *records_or_path* may be:
    - ``None``             – load the default feed from disk
    - a ``Path``           – load the feed at that path
    - a ``dict``           – use the already-loaded mapping directly
    """

    def __init__(self, records_or_path=None):
        if records_or_path is None:
            self.records: dict[str, ThreatIntelRecord] = load_threat_feed()
        elif isinstance(records_or_path, dict):
            self.records = records_or_path
        else:
            self.records = load_threat_feed(Path(records_or_path))

    def lookup_ip(self, ip_address: str) -> ThreatIntelRecord | None:
        return self.records.get(ip_address)

    def is_known_threat(self, ip_address: str) -> bool:
        return ip_address in self.records
