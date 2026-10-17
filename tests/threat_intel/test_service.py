from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.storage.database import Base
from src.storage.threat_intel_repository import ThreatIntelRepository
from src.threat_intel.enrichment import enrich_ip
from src.threat_intel.feed_loader import load_threat_feed
from src.threat_intel.models import ThreatIntelRecord
from src.threat_intel.service import ThreatIntelService


def test_known_and_unknown_ip_lookup_and_bounded_enrichment():
    service = ThreatIntelService(load_threat_feed())
    record = service.lookup_ip("203.0.113.50")

    assert service.is_known_threat("203.0.113.50")
    assert not service.is_known_threat("192.0.2.10")
    assert record is not None
    assert enrich_ip("203.0.113.50", record).risk_bonus == 18.0
    assert enrich_ip("192.0.2.10", None).risk_bonus == 0.0
    assert enrich_ip("203.0.113.60", service.lookup_ip("203.0.113.60")).risk_bonus == 16.0


def test_enrichment_bonus_caps_at_twenty():
    high_confidence = ThreatIntelRecord(
        ip_address="203.0.113.99",
        threat_type="test",
        confidence=100,
        source="LAB-TI",
        description="Controlled test record",
    )

    result = enrich_ip("203.0.113.99", high_confidence)

    assert result.matched
    assert result.risk_bonus == 20.0


def test_threat_repository_upserts_and_lists_records(tmp_path):
    database_file = tmp_path / "threat_intel.db"
    engine = create_engine(f"sqlite:///{database_file.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    repository = ThreatIntelRepository()
    original = ThreatIntelRecord(
        ip_address="203.0.113.50",
        threat_type="brute_force",
        confidence=80,
        source="LAB-TI",
        description="First description",
    )
    updated = ThreatIntelRecord(
        ip_address="203.0.113.50",
        threat_type="brute_force",
        confidence=95,
        source="LAB-TI",
        description="Updated description",
    )

    try:
        assert repository.save_many(session, [original]) == 1
        assert repository.save_many(session, [updated]) == 0
        stored = repository.get_by_ip(session, "203.0.113.50")
        assert stored is not None
        assert stored.confidence == 95
        assert stored.description == "Updated description"
        assert len(repository.list_records(session)) == 1
    finally:
        session.close()
        engine.dispose()