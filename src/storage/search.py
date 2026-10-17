from sqlalchemy import select
from sqlalchemy.orm import Session

from src.storage.models import EventModel


class EventSearchService:

    def __init__(self, session: Session):
        self.session = session

    def search(
        self,
        source_ip: str | None = None,
        username: str | None = None,
        event_type: str | None = None,
        event_category: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[EventModel]:

        query = select(EventModel)

        if source_ip:
            query = query.where(
                EventModel.source_ip == source_ip
            )

        if username:
            query = query.where(
                EventModel.username == username
            )

        if event_type:
            query = query.where(
                EventModel.event_type == event_type
            )

        if event_category:
            query = query.where(
                EventModel.event_category == event_category
            )

        if status:
            query = query.where(
                EventModel.status == status
            )

        query = (
            query
            .order_by(EventModel.timestamp)
            .limit(limit)
        )

        return list(
            self.session.scalars(query)
        )
