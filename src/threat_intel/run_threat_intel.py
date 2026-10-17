"""Check stored event source IPs against the local lab feed."""

from sqlalchemy import select

from src.storage.database import get_session, initialize_database
from src.storage.models import EventModel
from src.storage.threat_intel_repository import ThreatIntelRepository
from src.threat_intel.enrichment import enrich_ip
from src.threat_intel.feed_loader import load_threat_feed
from src.threat_intel.models import ThreatIntelRecord
from src.threat_intel.service import ThreatIntelService


def main() -> None:
    feed_records = load_threat_feed()
    service = ThreatIntelService(feed_records)
    initialize_database()
    session = get_session()
    try:
        stored_records = ThreatIntelRepository().list_records(session)
        records = (
            {
                record.ip_address: ThreatIntelRecord(
                    ip_address=record.ip_address,
                    threat_type=record.threat_type,
                    confidence=record.confidence,
                    source=record.source,
                    description=record.description,
                )
                for record in stored_records
            }
            if stored_records
            else feed_records
        )
        service = ThreatIntelService(records)
        addresses = list(
            session.scalars(
                select(EventModel.source_ip)
                .where(EventModel.source_ip.is_not(None))
                .distinct()
                .order_by(EventModel.source_ip)
            )
        )
    finally:
        session.close()

    print(f"Loaded {len(feed_records)} local threat-intelligence records.")
    print(f"Checking {len(addresses)} unique event source IPs.")
    for address in addresses:
        record = service.lookup_ip(address)
        enrichment = enrich_ip(address, record)
        print(f"\nIP Address : {enrichment.ip_address}")
        print(f"TI Match   : {enrichment.matched}")
        if not enrichment.matched:
            print("No threat-intelligence match found.")
            continue
        print(f"Threat     : {enrichment.threat_type}")
        print(f"Confidence : {enrichment.confidence}")
        print(f"Source     : {enrichment.source}")
        print(f"Risk Bonus : {enrichment.risk_bonus:.2f}")
        print(f"Description: {enrichment.description}")


if __name__ == "__main__":
    main()