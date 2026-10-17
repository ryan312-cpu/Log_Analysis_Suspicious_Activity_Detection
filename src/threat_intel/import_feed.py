"""Import the validated local IOC feed into the existing database."""

from src.storage.database import get_session, initialize_database
from src.storage.threat_intel_repository import ThreatIntelRepository
from src.threat_intel.feed_loader import load_threat_feed


def main() -> None:
    records = load_threat_feed()
    initialize_database()
    session = get_session()
    try:
        inserted = ThreatIntelRepository().save_many(session, records.values())
        print(f"Imported {len(records)} threat-intelligence records.")
        print(f"New records inserted: {inserted}")
    finally:
        session.close()


if __name__ == "__main__":
    main()