import csv
from pathlib import Path

from src.threat_intel.models import ThreatIntelRecord

FEED_PATH = Path("data/threat_intel/ip_feed.csv")


def load_threat_feed(
    feed_path: Path = FEED_PATH,
) -> dict[str, ThreatIntelRecord]:

    records = {}

    if not feed_path.exists():
        raise FileNotFoundError(
            f"Threat intelligence feed not found: {feed_path}"
        )

    with feed_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            ip_address = row["ip_address"].strip()
            records[ip_address] = ThreatIntelRecord(
                ip_address=ip_address,
                threat_type=row["threat_type"].strip(),
                confidence=int(row["confidence"]),
                source=row["source"].strip(),
                description=row["description"].strip(),
            )

    return records
