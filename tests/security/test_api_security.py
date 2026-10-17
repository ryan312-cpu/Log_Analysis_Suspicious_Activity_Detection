from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security.rate_limiter import RateLimitMiddleware
from src.api.security.secure_headers import SecurityHeadersMiddleware
from tests.conftest import ADMIN_HEADERS, ANALYST_HEADERS

client = TestClient(app)

PROTECTED_GET_PATHS = [
    "/api/v1/events",
    "/api/v1/alerts",
    "/api/v1/incidents",
    "/api/v1/threat-intel",
    "/api/v1/reports",
    "/api/v1/investigation/source/192.168.10.25",
]


def test_health_is_public():
    response = client.get("/health")
    assert response.status_code == 200


def test_unauthenticated_requests_return_401():
    for path in PROTECTED_GET_PATHS:
        response = client.get(path)
        assert response.status_code == 401, path
        assert "traceback" not in response.text.lower()
        assert response.headers.get("www-authenticate") == "ApiKey"


def test_invalid_api_key_returns_401():
    response = client.get(
        "/api/v1/investigation/source/192.168.10.25",
        headers={"X-API-Key": "wrong-key"},
    )
    assert response.status_code == 401


def test_authenticated_investigation_allowed():
    response = client.get(
        "/api/v1/investigation/source/192.168.10.25",
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_ip"] == "192.168.10.25"


def test_analyst_cannot_mutate_alerts():
    response = client.patch(
        "/api/v1/alerts/does-not-exist/status",
        json={"status": "CLOSED"},
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"


def test_analyst_cannot_mutate_incidents():
    response = client.patch(
        "/api/v1/incidents/does-not-exist/status",
        json={"status": "CLOSED"},
        headers=ANALYST_HEADERS,
    )
    assert response.status_code == 403


def test_admin_mutation_is_authorized_not_unauthenticated():
    response = client.patch(
        "/api/v1/alerts/does-not-exist/status",
        json={"status": "CLOSED"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"


def test_error_responses_do_not_leak_stack_traces():
    response = client.get("/api/v1/alerts/missing-alert", headers=ANALYST_HEADERS)
    assert response.status_code == 404
    body = response.json()
    assert set(body.keys()) == {"detail"}
    assert "Traceback" not in response.text


def test_unhandled_exception_returns_generic_500():
    from src.api.dependencies import get_db

    def boom():
        raise RuntimeError("secret internals")

    app.dependency_overrides[get_db] = boom
    try:
        leaking_client = TestClient(app, raise_server_exceptions=False)
        response = leaking_client.get("/api/v1/events", headers=ANALYST_HEADERS)
        assert response.status_code == 500
        assert response.json() == {"detail": "An internal server error occurred."}
        assert "secret internals" not in response.text
        assert "Traceback" not in response.text
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_security_headers_present():
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "no-store" in response.headers["Cache-Control"]
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_rate_limit_returns_429():
    limited = FastAPI()
    limited.add_middleware(SecurityHeadersMiddleware)
    limited.add_middleware(
        RateLimitMiddleware,
        max_requests=3,
        window_seconds=60,
        enabled=True,
    )

    @limited.get("/ping")
    def ping():
        return {"ok": True}

    limited_client = TestClient(limited)
    # Bypass the process-wide test flag used by the main app.
    import src.api.security.rate_limiter as limiter_module

    original = limiter_module.is_rate_limit_disabled
    limiter_module.is_rate_limit_disabled = lambda: False
    try:
        statuses = [limited_client.get("/ping").status_code for _ in range(4)]
    finally:
        limiter_module.is_rate_limit_disabled = original

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
