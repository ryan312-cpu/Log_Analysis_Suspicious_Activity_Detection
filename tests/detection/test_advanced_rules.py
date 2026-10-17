from dataclasses import FrozenInstanceError

import pytest

from src.detection.engine.rule_engine import DetectionEngine
from src.detection.run_detection import build_detection_engine
from src.detection.rules.application.repeated_application_error_rule import (
    RepeatedApplicationErrorRule,
)
from src.detection.rules.authentication.multiple_account_target_rule import (
    MultipleAccountTargetRule,
)
from src.detection.rules.authentication.multiple_source_login_rule import (
    MultipleSourceLoginRule,
)
from src.detection.rules.firewall.repeated_denied_rule import (
    RepeatedFirewallDeniedRule,
)
from src.detection.rules.system.repeated_service_failure_rule import (
    RepeatedServiceFailureRule,
)
from src.detection.rules.web.repeated_404_rule import Repeated404Rule
from src.detection.rules.web.repeated_5xx_rule import Repeated5xxRule
from src.detection.rules.web.sensitive_path_rule import SensitivePathRule
from src.storage.models import EventModel


def make_event(
    event_id: str,
    *,
    timestamp: str = "2026-10-01 10:00:00",
    event_type: str,
    category: str,
    source_ip: str | None = "198.51.100.20",
    username: str | None = None,
    service: str | None = "test-service",
    status: str | None = None,
    action: str | None = None,
    path: str | None = None,
    response_code: int | None = None,
) -> EventModel:
    return EventModel(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        event_category=category,
        source_ip=source_ip,
        username=username,
        service=service,
        status=status,
        action=action,
        http_path=path,
        response_code=response_code,
    )


def test_rule_inventory_has_fifteen_unique_metadata_records():
    metadata = build_detection_engine().rule_metadata

    assert len(metadata) == 15
    assert len({item.rule_id for item in metadata}) == 15
    assert {
        item.category for item in metadata
    } == {"authentication", "web", "firewall", "application", "system"}
    assert all(item.rule_name and item.description and item.severity for item in metadata)
    assert any(item.mitre_technique == "T1110.003" for item in metadata)

    with pytest.raises(FrozenInstanceError):
        metadata[0].severity = "LOW"


def test_engine_rejects_duplicate_rule_ids():
    rule = MultipleAccountTargetRule()

    with pytest.raises(ValueError, match="IDs must be unique"):
        DetectionEngine([rule, rule])


def test_multiple_account_target_rule():
    events = [
        make_event(
            f"AUTH-{index}",
            event_type="LOGIN_FAILED",
            category="authentication",
            username=username,
        )
        for index, username in enumerate(("alice", "bob", "charlie", "david"))
    ]

    alerts = MultipleAccountTargetRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-006"
    assert MultipleAccountTargetRule().metadata.category == "authentication"
    assert len(alerts[0].event_ids) == 4


def test_multiple_source_login_rule():
    events = [
        make_event(
            f"LOGIN-{index}",
            event_type="LOGIN_SUCCESS",
            category="authentication",
            source_ip=source_ip,
            username="alice",
        )
        for index, source_ip in enumerate(
            ("192.0.2.10", "192.0.2.11", "192.0.2.12")
        )
    ]

    alerts = MultipleSourceLoginRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-007"
    assert alerts[0].username == "alice"
    assert len(alerts[0].event_ids) == 3


def test_repeated_404_rule():
    events = [
        make_event(
            f"WEB-{index}",
            event_type="HTTP_REQUEST",
            category="web",
            response_code=404,
            path=f"/missing-{index}",
        )
        for index in range(4)
    ]

    alerts = Repeated404Rule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WEB-003"
    assert len(alerts[0].event_ids) == 4


def test_repeated_5xx_rule():
    events = [
        make_event(
            f"WEB-{index}",
            event_type="HTTP_REQUEST",
            category="web",
            response_code=response_code,
        )
        for index, response_code in enumerate((500, 503, 599))
    ]

    alerts = Repeated5xxRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WEB-004"


def test_sensitive_path_rule_is_case_insensitive():
    events = [
        make_event(
            f"WEB-{index}",
            event_type="HTTP_REQUEST",
            category="web",
            path=path,
        )
        for index, path in enumerate(("/WP-ADMIN", "/phpmyadmin/", "/backup.zip"))
    ]

    alerts = SensitivePathRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WEB-005"


def test_repeated_firewall_denial_accepts_parser_uppercase_action():
    events = [
        make_event(
            f"FW-{index}",
            event_type="FIREWALL_EVENT",
            category="security",
            action="DENY",
            status="DENY",
            service=f"tcp/{port}",
        )
        for index, port in enumerate((22, 23, 80, 443))
    ]

    alerts = RepeatedFirewallDeniedRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "FW-001"
    assert len(alerts[0].event_ids) == 4


def test_repeated_application_error_rule():
    events = [
        make_event(
            f"APP-{index}",
            event_type="APP_ERROR",
            category="application",
            service="payment",
            status="error",
        )
        for index in range(3)
    ]

    alerts = RepeatedApplicationErrorRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "APP-001"
    assert alerts[0].evidence[0] == "Service: payment"


def test_repeated_service_failure_matches_normalized_system_events():
    events = [
        make_event(
            f"SYS-{index}",
            event_type="SYSTEM_EVENT",
            category="system",
            service="auditd",
            status="stopped",
        )
        for index in range(3)
    ]

    alerts = RepeatedServiceFailureRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SYS-001"
    assert len(alerts[0].event_ids) == 3