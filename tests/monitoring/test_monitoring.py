import logging
from fastapi.testclient import TestClient

from src.api.main import app
from src.monitoring.alert_logger import (
    log_alert_generated,
    log_detection_run,
    log_parser_error,
)
from src.monitoring.health import (
    check_database_health,
    check_detection_engine_health,
    check_parser_health,
    get_full_health,
)
from src.monitoring.logging_config import configure_logging, get_logger
from src.monitoring.metrics import get_metrics, reset_metrics

client = TestClient(app)


def test_configure_logging_returns_logger():
    root = configure_logging(level="INFO", log_to_file=False)
    assert isinstance(root, logging.Logger)
    assert root.level == logging.INFO


def test_get_logger_returns_named_logger():
    logger = get_logger("security.investigation")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "security.investigation"


def test_metrics_increment():
    reset_metrics()
    metrics = get_metrics()
    assert metrics.events_processed_total == 0
    metrics.increment("events_processed_total", 5)
    assert metrics.events_processed_total == 5


def test_metrics_reset():
    metrics = get_metrics()
    metrics.increment("alerts_generated_total", 10)
    assert metrics.alerts_generated_total >= 10
    reset_metrics()
    assert get_metrics().alerts_generated_total == 0


def test_metrics_snapshot_has_required_keys():
    reset_metrics()
    snapshot = get_metrics().snapshot()
    expected_keys = {
        "events_processed_total",
        "alerts_generated_total",
        "incidents_created_total",
        "parser_errors_total",
        "detection_errors_total",
        "api_requests_total",
        "api_request_avg_duration_s",
    }
    assert expected_keys.issubset(snapshot.keys())


def test_record_api_request_duration():
    reset_metrics()
    metrics = get_metrics()
    metrics.record_api_request(0.010)
    metrics.record_api_request(0.020)
    metrics.record_api_request(0.030)
    assert metrics.api_requests_total == 3
    assert 0.019 <= metrics.get_api_avg_duration() <= 0.021


def test_database_health_returns_dict():
    result = check_database_health()
    assert isinstance(result, dict)
    assert "status" in result
    assert result["status"] in ("healthy", "unhealthy")


def test_detection_engine_health_returns_dict():
    result = check_detection_engine_health()
    assert isinstance(result, dict)
    assert result["status"] == "healthy"
    assert "rule_count" in result
    assert result["rule_count"] >= 15


def test_parser_health_returns_dict():
    result = check_parser_health()
    assert isinstance(result, dict)
    assert result["status"] in ("healthy", "degraded")


def test_full_health_structure():
    health = get_full_health()
    assert "status" in health
    assert "timestamp" in health
    assert "components" in health
    components = health["components"]
    assert "database" in components
    assert "detection_engine" in components
    assert "parser" in components


def test_full_health_overall_status_valid():
    health = get_full_health()
    assert health["status"] in ("healthy", "degraded", "unhealthy")


def test_alert_logger_functions():
    # Should execute without throwing any exception
    log_alert_generated("AUTH-001", "HIGH", source_ip="192.168.1.100")
    log_alert_generated("AUTH-002", "LOW", source_ip="192.168.1.101")
    log_detection_run(event_count=500, alert_count=3, duration_s=0.125)
    log_parser_error("auth_syslog", "Malformed line")


def test_api_health_detailed_endpoint():
    response = client.get("/health/detailed")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "components" in data


def test_api_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "api_requests_total" in data
    assert "api_request_avg_duration_s" in data
    assert data["api_requests_total"] >= 1
