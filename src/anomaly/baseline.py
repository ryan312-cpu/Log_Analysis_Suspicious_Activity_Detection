from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev

from src.storage.models import EventModel


def parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def build_source_ip_baseline(
    events: list[EventModel],
) -> dict:

    grouped = defaultdict(list)

    for event in events:

        if not event.source_ip:
            continue

        grouped[event.source_ip].append(event)

    baseline = {}

    for source_ip, source_events in grouped.items():

        hourly_counts = defaultdict(int)

        for event in source_events:

            timestamp = parse_timestamp(event.timestamp)
            hour = timestamp.hour
            hourly_counts[hour] += 1

        values = list(hourly_counts.values())

        if not values:
            continue

        baseline[source_ip] = {
            "mean": mean(values),
            "stddev": stdev(values) if len(values) > 1 else 0.0,
            "max": max(values),
            "total_events": len(source_events),
        }

    return baseline
