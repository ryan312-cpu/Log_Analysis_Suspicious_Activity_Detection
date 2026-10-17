"""Database persistence and lookup for threat-intelligence records."""

from collections.abc import Iterable
from ipaddress import ip_address

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.threat_intel.models import ThreatIntelRecord
from src.storage.models import ThreatIntelModel


class ThreatIntelRepository:
    @staticmethod
    def _validated_values(record: ThreatIntelRecord) -> dict[str, str | int]:
        normalized_ip = ip_address(record.ip_address).compressed
        if not 0 <= record.confidence <= 100:
            raise ValueError("Threat confidence must be between 0 and 100")
        for name, value in (
            ("threat_type", record.threat_type),
            ("source", record.source),
            ("description", record.description),
        ):
            if not value.strip():
                raise ValueError(f"Threat {name} cannot be empty")
        return {
            "ip_address": normalized_ip,
            "threat_type": record.threat_type.strip(),
            "confidence": record.confidence,
            "source": record.source.strip(),
            "description": record.description.strip(),
        }

    def save(self, db: Session, record: ThreatIntelRecord) -> ThreatIntelModel:
        self.save_many(db, [record])
        return self.get_by_ip(db, record.ip_address)

    def save_many(
        self,
        db: Session,
        records: Iterable[ThreatIntelRecord],
    ) -> int:
        records = list(records)
        if not records:
            return 0

        validated = [self._validated_values(record) for record in records]
        addresses = {str(values["ip_address"]) for values in validated}
        existing_records = {
            row.ip_address: row
            for row in db.scalars(
                select(ThreatIntelModel).where(
                    ThreatIntelModel.ip_address.in_(addresses)
                )
            )
        }
        inserted = 0
        try:
            for values in validated:
                address = str(values["ip_address"])
                existing = existing_records.get(address)
                if existing is None:
                    existing_records[address] = ThreatIntelModel(**values)
                    db.add(existing_records[address])
                    inserted += 1
                else:
                    for field, value in values.items():
                        setattr(existing, field, value)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return inserted

    def get_by_ip(self, db: Session, address: str) -> ThreatIntelModel | None:
        normalized_ip = ip_address(address.strip()).compressed
        return db.scalar(
            select(ThreatIntelModel).where(
                ThreatIntelModel.ip_address == normalized_ip
            )
        )

    def list_records(self, db: Session) -> list[ThreatIntelModel]:
        return list(
            db.scalars(
                select(ThreatIntelModel).order_by(
                    ThreatIntelModel.confidence.desc(),
                    ThreatIntelModel.ip_address,
                )
            )
        )