from src.normalization.schema import NormalizedEvent
from src.storage.database import Base, get_session
from src.storage.repository import EventRepository


def test_event_repository():

    session = get_session()

    Base.metadata.create_all(
        bind=session.get_bind()
    )

    repository = EventRepository(session)

    event = NormalizedEvent(
        event_id="TEST-000001",
        timestamp="2026-09-25 12:00:00",
        event_type="LOGIN_FAILED",
        event_category="authentication",
        source_ip="10.10.10.10",
        username="testuser",
        service="ssh",
        status="failed",
        source_type="authentication",
        raw_log="test event",
    )

    repository.save_event(event)
    session.commit()

    stored = repository.get_event(
        "TEST-000001"
    )

    assert stored is not None
    assert stored.source_ip == "10.10.10.10"
    assert stored.username == "testuser"

    session.delete(stored)
    session.commit()

    session.close()
