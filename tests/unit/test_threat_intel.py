from src.threat_intel import ThreatEnrichment, ThreatIntelService, load_threat_feed


def test_feed_loader_reads_local_synthetic_feed():
    records = load_threat_feed()

    assert isinstance(records, dict)
    assert "198.51.100.10" in records
    assert records["198.51.100.10"].threat_type == "phishing"


def test_lookup_service_and_enrichment():
    service = ThreatIntelService()
    record = service.lookup_ip("198.51.100.10")

    assert record is not None
    assert service.is_known_threat("198.51.100.10") is True

    enrichment = ThreatEnrichment()
    bonus = enrichment.score_ip("198.51.100.10")

    assert bonus > 0.0
