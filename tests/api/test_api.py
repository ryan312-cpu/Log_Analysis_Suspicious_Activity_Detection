from fastapi.testclient import TestClient

from src.api.main import app
from tests.conftest import ANALYST_HEADERS

client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_events_endpoint():
    response = client.get("/api/v1/events", headers=ANALYST_HEADERS)

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_alerts_endpoint():
    response = client.get("/api/v1/alerts", headers=ANALYST_HEADERS)

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_event_filter():
    response = client.get(
        "/api/v1/events",
        params={"source_ip": "192.168.10.55"},
        headers=ANALYST_HEADERS,
    )

    assert response.status_code == 200
    events = response.json()

    for event in events:
        assert event["source_ip"] == "192.168.10.55"
