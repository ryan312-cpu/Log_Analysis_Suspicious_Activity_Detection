from datetime import datetime, timedelta
from typing import List

from src.storage.models import EventModel


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def events_within_window(
    events: List[EventModel],
    start_time: datetime,
    window_seconds: int,
) -> List[EventModel]:

    end_time = start_time + timedelta(
        seconds=window_seconds
    )

    return [
        event
        for event in events
        if start_time
        <= parse_timestamp(event.timestamp)
        <= end_time
    ]
