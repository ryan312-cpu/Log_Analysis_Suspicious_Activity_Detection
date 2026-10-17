from src.threat_intel.feed_loader import load_threat_feed


class ThreatIntelService:
    def __init__(self, feed_path=None):
        self.feed_path = feed_path
        self.records = load_threat_feed(feed_path) if feed_path else load_threat_feed()

    def lookup_ip(self, ip_address: str):
        return self.records.get(ip_address)

    def is_known_threat(self, ip_address: str) -> bool:
        return ip_address in self.records
