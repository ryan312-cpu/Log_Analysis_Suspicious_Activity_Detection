from src.detection.rules.failed_login_rule import MultipleFailedLoginRule
from src.detection.rules.password_spraying_rule import PasswordSprayingRule
from src.detection.rules.restricted_resource_rule import RestrictedResourceRule
from src.detection.rules.successful_login_after_failures_rule import (
    SuccessfulLoginAfterFailuresRule,
)
from src.storage.models import EventModel


def make_failed_login(
    event_id: str,
    source_ip: str,
):

    return EventModel(
        event_id=event_id,
        timestamp="2026-09-25 10:00:00",
        event_type="LOGIN_FAILED",
        event_category="authentication",
        source_ip=source_ip,
        username="alice",
        service="ssh",
        status="failed",
        source_type="authentication",
    )


def test_multiple_failed_login_rule():

    events = [
        make_failed_login(
            f"TEST-{i}",
            "10.0.0.50",
        )
        for i in range(5)
    ]

    rule = MultipleFailedLoginRule()

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"
    assert alerts[0].severity == "HIGH"


def test_failed_login_below_threshold():

    events = [
        make_failed_login(
            f"TEST-{i}",
            "10.0.0.50",
        )
        for i in range(3)
    ]

    rule = MultipleFailedLoginRule()

    alerts = rule.evaluate(events)

    assert len(alerts) == 0


def test_restricted_resource_rule():

    events = []

    for i in range(3):

        events.append(
            EventModel(
                event_id=f"WEB-{i}",
                timestamp=(
                    "2026-09-25 10:10:00"
                ),
                event_type="HTTP_REQUEST",
                event_category="web",
                source_ip="10.0.0.90",
                http_method="GET",
                http_path="/admin",
                response_code=403,
                status="error",
                source_type="web",
            )
        )

    rule = RestrictedResourceRule()

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WEB-001"


def make_auth_event(
    event_id,
    timestamp,
    event_type,
    source_ip="10.0.0.50",
    username="alice",
):

    return EventModel(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        event_category="authentication",
        source_ip=source_ip,
        username=username,
        service="ssh",
        status=(
            "failed"
            if event_type == "LOGIN_FAILED"
            else "success"
        ),
        source_type="authentication",
    )


def test_successful_login_after_failures():

    events = [
        make_auth_event(
            "FAIL-1",
            "2026-09-25 10:00:00",
            "LOGIN_FAILED",
        ),
        make_auth_event(
            "FAIL-2",
            "2026-09-25 10:00:20",
            "LOGIN_FAILED",
        ),
        make_auth_event(
            "FAIL-3",
            "2026-09-25 10:00:40",
            "LOGIN_FAILED",
        ),
        make_auth_event(
            "SUCCESS-1",
            "2026-09-25 10:01:00",
            "LOGIN_SUCCESS",
        ),
    ]

    rule = SuccessfulLoginAfterFailuresRule()

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-004"
    assert alerts[0].severity == "CRITICAL"


def test_password_spraying():

    users = [
        "admin",
        "root",
        "test",
        "administrator",
    ]

    events = []

    for index, user in enumerate(users):

        events.append(
            make_auth_event(
                f"SPRAY-{index}",
                f"2026-09-25 10:00:{index * 10:02d}",
                "LOGIN_FAILED",
                source_ip="10.0.0.90",
                username=user,
            )
        )

    rule = PasswordSprayingRule()

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-005"
