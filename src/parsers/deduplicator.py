from typing import List

from src.normalization.schema import NormalizedEvent


def remove_duplicates(
    events: List[NormalizedEvent],
) -> List[NormalizedEvent]:

    seen = set()
    unique_events = []

    for event in events:

        fingerprint = (
            event.timestamp,
            event.event_type,
            event.source_ip,
            event.username,
            event.service,
            event.raw_log,
        )

        if fingerprint in seen:
            continue

        seen.add(fingerprint)
        unique_events.append(event)

    return unique_events
