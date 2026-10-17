from fastapi.testclient import TestClient

from src.api.main import app
from tests.conftest import ANALYST_HEADERS

client = TestClient(app)


def test_reporting_endpoint_returns_summary():
    response = client.get("/api/v1/reports", headers=ANALYST_HEADERS)

    assert response.status_code == 200
    data = response.json()

    assert "generated_at" in data
    assert "executive_summary" in data
    assert "detection_statistics" in data
    assert "top_source_ips" in data
    assert "recommendations" in data
    assert data["detection_statistics"]["total_events"] >= 1
    assert data["detection_statistics"]["total_alerts"] >= 1
