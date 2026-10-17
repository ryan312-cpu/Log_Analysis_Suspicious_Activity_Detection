from src.normalization.schema import NormalizedEvent
from src.parsers.deduplicator import remove_duplicates


def test_duplicate_events_are_removed():

    event = NormalizedEvent(
        event_id="AUTH-000001",
        timestamp="2026-09-25 08:00:00",
        event_type="LOGIN_SUCCESS",
        event_category="authentication",
        source_ip="192.168.10.25",
        username="alice",
        service="ssh",
        status="success",
        source_type="authentication",
        raw_log="test log",
    )

    events = [
        event,
        event,
    ]

    result = remove_duplicates(events)

    assert len(result) == 1
