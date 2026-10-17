from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.storage.models import ThreatIntelModel


class ThreatIntelRepository:
    def __init__(self, session: Session):
        self.session = session

    def add_record(self, record: ThreatIntelModel) -> None:
        self.session.add(record)

    def add_many(self, records: Iterable[ThreatIntelModel]) -> None:
        self.session.add_all(list(records))

    def list_all(self) -> list[ThreatIntelModel]:
        return self.session.scalars(select(ThreatIntelModel)).all()

    def find_by_ip(self, ip_address: str) -> ThreatIntelModel | None:
        return self.session.scalar(
            select(ThreatIntelModel).where(ThreatIntelModel.ip_address == ip_address)
        )
