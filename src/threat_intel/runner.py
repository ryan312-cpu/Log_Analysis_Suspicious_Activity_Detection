from src.storage.database import get_session
from src.storage.models import ThreatIntelModel
from src.threat_intel.feed_loader import load_threat_feed


def import_threat_feed(feed_path=None) -> list[ThreatIntelModel]:
    records = load_threat_feed(feed_path) if feed_path else load_threat_feed()
    imported = []

    with get_session() as session:
        session.expire_on_commit = False

        for ip_address, record in records.items():
            existing = (session.query(ThreatIntelModel).filter_by(ip_address=ip_address).first())
            if existing is None:
                model = ThreatIntelModel(
                    ip_address=ip_address,
                    threat_type=record.threat_type,
                    confidence=record.confidence,
                    source=record.source,
                    description=record.description,
                )
                session.add(model)
                imported.append(model)
        session.commit()

    return imported
