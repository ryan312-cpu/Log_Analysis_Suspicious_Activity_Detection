import csv

from src.normalization.schema import NormalizedEvent
from src.storage.database import get_session, initialize_database
from src.storage.repository import EventRepository

CSV_FILE = "data/normalized/raw_parsed_events.csv"


def load_events():

    events = []

    with open(
        CSV_FILE,
        "r",
        encoding="utf-8",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            def optional_int(value):
                if not value:
                    return None
                return int(value)

            event = NormalizedEvent(
                event_id=row["event_id"],
                timestamp=row["timestamp"],
                event_type=row["event_type"],
                event_category=row["event_category"],
                source_ip=row.get("source_ip") or None,
                source_port=optional_int(
                    row.get("source_port")
                ),
                destination_ip=(
                    row.get("destination_ip") or None
                ),
                destination_port=optional_int(
                    row.get("destination_port")
                ),
                username=row.get("username") or None,
                hostname=row.get("hostname") or None,
                service=row.get("service") or None,
                action=row.get("action") or None,
                status=row.get("status") or None,
                http_method=(
                    row.get("http_method") or None
                ),
                http_path=(
                    row.get("http_path") or None
                ),
                response_code=optional_int(
                    row.get("response_code")
                ),
                user_agent=(
                    row.get("user_agent") or None
                ),
                source_type=(
                    row.get("source_type") or None
                ),
                raw_log=row.get("raw_log") or None,
            )

            events.append(event)

    return events


def main():

    print("=" * 60)
    print("EVENT STORAGE IMPORT")
    print("=" * 60)

    initialize_database()

    events = load_events()

    print(f"Events loaded from CSV: {len(events)}")

    session = get_session()

    try:

        repository = EventRepository(session)

        inserted = repository.save_events(events)

        print(f"New events inserted: {inserted}")
        print(
            f"Total events in database: "
            f"{repository.count_events()}"
        )

    finally:
        session.close()

    print("=" * 60)


if __name__ == "__main__":
    main()
