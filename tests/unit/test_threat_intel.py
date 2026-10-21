from src.threat_intel import ThreatEnrichment, ThreatIntelService, load_threat_feed


def test_feed_loader_reads_local_synthetic_feed():
    records = load_threat_feed()

    assert isinstance(records, dict)
    # The canonical feed uses 203.0.113.x documentation IPs (RFC 5737).
    assert "203.0.113.50" in records
    assert records["203.0.113.50"].threat_type == "brute_force"


def test_lookup_service_and_enrichment():
    service = ThreatIntelService()
    record = service.lookup_ip("203.0.113.50")

    assert record is not None
    assert service.is_known_threat("203.0.113.50") is True

    enrichment = ThreatEnrichment()
    bonus = enrichment.score_ip("203.0.113.50")

    assert bonus > 0.0
