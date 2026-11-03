from datetime import datetime, timedelta

from src.detection.engine.rule_engine import DetectionEngine
from src.detection.policy_manager import PolicyManager
from src.detection.rules.failed_login_rule import MultipleFailedLoginRule
from src.detection.rules.successful_login_after_failures_rule import (
    SuccessfulLoginAfterFailuresRule,
)
from src.storage.models import EventModel


def make_auth_event(event_id: str, event_type: str, timestamp: datetime) -> EventModel:
    return EventModel(
        event_id=event_id,
        timestamp=timestamp.isoformat(),
        event_type=event_type,
        event_category="authentication",
        source_ip="192.0.2.10",
        username="analyst",
    )


def use_test_policy(tmp_path, monkeypatch) -> PolicyManager:
    manager = PolicyManager(tmp_path / "security_policy.json")
    monkeypatch.setattr(PolicyManager, "_instance", manager)
    return manager


def test_detection_engine_skips_disabled_policy_rule(tmp_path, monkeypatch):
    policy = use_test_policy(tmp_path, monkeypatch)
    policy.update_rule_policy("AUTH-001", {"enabled": False})
    timestamp = datetime(2026, 11, 3, 10)
    events = [
        make_auth_event(f"failed-{index}", "LOGIN_FAILED", timestamp)
        for index in range(5)
    ]

    engine = DetectionEngine([MultipleFailedLoginRule()])
    alerts = engine.run(events)

    assert alerts == []
    assert engine.rule_metadata[0].enabled is False


def test_detection_rule_uses_configured_threshold(tmp_path, monkeypatch):
    policy = use_test_policy(tmp_path, monkeypatch)
    policy.update_rule_policy("AUTH-001", {"threshold": 2})
    timestamp = datetime(2026, 11, 3, 10)
    events = [
        make_auth_event(f"failed-{index}", "LOGIN_FAILED", timestamp)
        for index in range(2)
    ]

    alerts = DetectionEngine([MultipleFailedLoginRule()]).run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"


def test_detection_rule_uses_named_configured_threshold(tmp_path, monkeypatch):
    policy = use_test_policy(tmp_path, monkeypatch)
    policy.update_rule_policy("AUTH-004", {"failed_threshold": 2})
    timestamp = datetime(2026, 11, 3, 10)
    events = [
        make_auth_event(
            f"failed-{index}",
            "LOGIN_FAILED",
            timestamp + timedelta(seconds=index * 10),
        )
        for index in range(2)
    ]
    events.append(
        make_auth_event(
            "success",
            "LOGIN_SUCCESS",
            timestamp + timedelta(seconds=30),
        )
    )

    alerts = DetectionEngine([SuccessfulLoginAfterFailuresRule()]).run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-004"
