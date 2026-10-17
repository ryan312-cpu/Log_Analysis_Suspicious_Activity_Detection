from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security.input_validator import (
    MAX_STRING_LENGTH,
    validate_ip_address,
    validate_string_input,
    validate_timestamp,
)
from tests.conftest import ANALYST_HEADERS

client = TestClient(app)

MALICIOUS_VALUES = [
    "'",
    '"',
    "../../etc/passwd",
    "..\\..\\etc\\passwd",
    "<script>alert(1)</script>",
    "%00",
    "a" * (MAX_STRING_LENGTH + 1),
]


@pytest.mark.parametrize("payload", MALICIOUS_VALUES)
def test_events_rejects_malicious_username(payload):
    response = client.get(
        "/api/v1/events",
        params={"username": payload},
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


@pytest.mark.parametrize("payload", MALICIOUS_VALUES + ["not-an-ip", "999.999.999.999"])
def test_investigation_rejects_malicious_or_invalid_ip(payload):
    encoded = quote(payload, safe="")
    response = client.get(
        f"/api/v1/investigation/source/{encoded}",
        headers=ANALYST_HEADERS,
    )
    # Encoded traversal/HTML may never match the route (404) or fail validation (422).
    assert response.status_code in {404, 422}
    assert "traceback" not in response.text.lower()


def test_invalid_ip_query_rejected():
    response = client.get(
        "/api/v1/events",
        params={"source_ip": "invalid IP"},
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 422
    assert "Invalid IP address" in response.json()["detail"]


def test_invalid_timestamp_rejected():
    response = client.get(
        "/api/v1/events",
        params={"since": "invalid timestamp"},
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 422
    assert "Invalid timestamp" in response.json()["detail"]


def test_valid_ip_and_timestamp_accepted():
    response = client.get(
        "/api/v1/events",
        params={
            "source_ip": "192.168.10.25",
            "since": "2024-01-01T00:00:00",
        },
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 200


def test_null_byte_rejected_by_validator():
    with pytest.raises(Exception) as exc:
        validate_string_input("user\x00name", "username")
    assert exc.value.status_code == 422


def test_validate_ip_and_timestamp_helpers():
    assert validate_ip_address("10.0.0.1") == "10.0.0.1"
    assert validate_timestamp("2026-10-14T09:00:00") == "2026-10-14T09:00:00"

    with pytest.raises(Exception):
        validate_ip_address("not-an-ip")
    with pytest.raises(Exception):
        validate_timestamp("yesterday")
