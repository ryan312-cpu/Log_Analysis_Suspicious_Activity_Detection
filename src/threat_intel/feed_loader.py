import csv
import ipaddress
from pathlib import Path

from src.threat_intel.models import ThreatIntelRecord

FEED_PATH = Path("data/threat_intel/ip_feed.csv")


def load_threat_feed(
    feed_path: Path = FEED_PATH,
) -> dict[str, ThreatIntelRecord]:

    records: dict[str, ThreatIntelRecord] = {}

    if not feed_path.exists():
        raise FileNotFoundError(
            f"Threat intelligence feed not found: {feed_path}"
        )

    with feed_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            ip_str = row["ip_address"].strip()

            # Validate IP address format
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip_str}")

            # Validate confidence is an integer
            confidence_raw = row["confidence"].strip()
            try:
                confidence = int(confidence_raw)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid confidence value '{confidence_raw}': must be an integer between 0 and 100"
                )

            # Validate confidence range
            if not (0 <= confidence <= 100):
                raise ValueError(
                    f"Confidence {confidence} out of range: must be between 0 and 100"
                )

            # Detect duplicate IPs
            if ip_str in records:
                raise ValueError(
                    f"Duplicate IP address '{ip_str}' found in threat feed"
                )

            records[ip_str] = ThreatIntelRecord(
                ip_address=ip_str,
                threat_type=row["threat_type"].strip(),
                confidence=confidence,
                source=row["source"].strip(),
                description=row["description"].strip(),
            )

    return records
