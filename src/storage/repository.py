from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.normalization.schema import NormalizedEvent
from src.storage.models import EventModel


class EventRepository:

    def __init__(self, session: Session):
        self.session = session

    def save_event(
        self,
        event: NormalizedEvent,
    ) -> EventModel:

        existing = self.session.scalar(
            select(EventModel).where(
                EventModel.event_id == event.event_id
            )
        )

        if existing:
            return existing

        record = EventModel(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            event_category=event.event_category,
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            username=event.username,
            hostname=event.hostname,
            service=event.service,
            action=event.action,
            status=event.status,
            http_method=event.http_method,
            http_path=event.http_path,
            response_code=event.response_code,
            user_agent=event.user_agent,
            source_type=event.source_type,
            raw_log=event.raw_log,
        )

        self.session.add(record)

        return record

    def save_events(
        self,
        events: Iterable[NormalizedEvent],
    ) -> int:

        count = 0

        for event in events:
            before = self.session.scalar(
                select(EventModel.id).where(
                    EventModel.event_id == event.event_id
                )
            )

            self.save_event(event)

            if before is None:
                count += 1

        self.session.commit()

        return count

    def count_events(self) -> int:

        return self.session.scalar(
            select(func.count(EventModel.id))
        ) or 0

    def get_event(
        self,
        event_id: str,
    ) -> EventModel | None:

        return self.session.scalar(
            select(EventModel).where(
                EventModel.event_id == event_id
            )
        )

    def get_events_by_source_ip(
        self,
        source_ip: str,
    ) -> list[EventModel]:

        return list(
            self.session.scalars(
                select(EventModel)
                .where(
                    EventModel.source_ip == source_ip
                )
                .order_by(EventModel.timestamp)
            )
        )

    def get_events_by_category(
        self,
        category: str,
    ) -> list[EventModel]:

        return list(
            self.session.scalars(
                select(EventModel)
                .where(
                    EventModel.event_category == category
                )
                .order_by(EventModel.timestamp)
            )
        )
