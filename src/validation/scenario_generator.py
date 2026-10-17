"""
Scenario generator for controlled security validation (Phase 21).
Generates in-memory events as SimpleNamespace instances to test detection rules cleanly.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import List, Optional

BASE_TIME = "2026-10-17 12:00:00"


def _make_event(
    idx: int,
    event_type: str,
    category: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    service: Optional[str] = None,
    status: Optional[str] = None,
    action: Optional[str] = None,
    http_method: Optional[str] = None,
    http_path: Optional[str] = None,
    response_code: Optional[int] = None,
    time_offset_seconds: int = 0,
) -> SimpleNamespace:
    base_dt = datetime.strptime(BASE_TIME, "%Y-%m-%d %H:%M:%S")
    event_dt = base_dt + timedelta(seconds=time_offset_seconds)
    ts_str = event_dt.strftime("%Y-%m-%d %H:%M:%S")

    return SimpleNamespace(
        id=idx,
        event_id=f"CV-{idx:06d}",
        timestamp=ts_str,
        event_type=event_type.upper(),
        event_category=category.lower(),
        source_ip=source_ip,
        source_port=None,
        destination_ip="10.0.0.1",
        destination_port=443,
        username=username,
        hostname="prod-server-01",
        service=service,
        action=action,
        status=status.lower() if status else None,
        http_method=http_method.upper() if http_method else None,
        http_path=http_path,
        response_code=response_code,
        user_agent="Mozilla/5.0 SecurityValidator/1.0",
        source_type=category.lower(),
        raw_log="",
        ingested_at=None,
    )


def scenario_brute_force(source_ip: str = "10.99.1.1", username: str = "admin", count: int = 6) -> List[SimpleNamespace]:
    """CV-001: Multiple failed logins targeting AUTH-001 (Threshold: 5)."""
    return [
        _make_event(
            idx=i,
            event_type="LOGIN_FAILED",
            category="authentication",
            source_ip=source_ip,
            username=username,
            service="ssh",
            status="failed",
            time_offset_seconds=i * 2,
        )
        for i in range(count)
    ]


def scenario_password_spraying(source_ip: str = "10.99.2.1", count: int = 5) -> List[SimpleNamespace]:
    """CV-002: Password spraying across multiple usernames targeting AUTH-005 (Threshold: 4 users in 120s)."""
    users = [f"target_user_{i}" for i in range(count)]
    return [
        _make_event(
            idx=i,
            event_type="LOGIN_FAILED",
            category="authentication",
            source_ip=source_ip,
            username=users[i],
            service="ssh",
            status="failed",
            time_offset_seconds=i * 5,
        )
        for i in range(count)
    ]


def scenario_login_after_failures(
    source_ip: str = "10.99.3.1",
    username: str = "finance_admin",
    failures: int = 4,
) -> List[SimpleNamespace]:
    """CV-003: Successful login after failures targeting AUTH-004 (Threshold: 3 failures then success)."""
    events = [
        _make_event(
            idx=i,
            event_type="LOGIN_FAILED",
            category="authentication",
            source_ip=source_ip,
            username=username,
            service="ssh",
            status="failed",
            time_offset_seconds=i * 2,
        )
        for i in range(failures)
    ]
    # Followed immediately by successful authentication within window
    events.append(
        _make_event(
            idx=failures,
            event_type="LOGIN_SUCCESS",
            category="authentication",
            source_ip=source_ip,
            username=username,
            service="ssh",
            status="success",
            time_offset_seconds=failures * 2 + 1,
        )
    )
    return events


def scenario_web_enumeration(source_ip: str = "10.99.4.1") -> List[SimpleNamespace]:
    """CV-004: Sensitive administrative path scanning targeting WEB-005 (Threshold: 3)."""
    sensitive_paths = ["/wp-admin", "/phpmyadmin", "/.env", "/admin", "/config"]
    return [
        _make_event(
            idx=i,
            event_type="HTTP_REQUEST",
            category="web",
            source_ip=source_ip,
            service="http",
            status="error",
            http_method="GET",
            http_path=path,
            response_code=404,
            time_offset_seconds=i * 2,
        )
        for i, path in enumerate(sensitive_paths)
    ]


def scenario_excessive_requests(source_ip: str = "10.99.5.1", count: int = 8) -> List[SimpleNamespace]:
    """CV-005: Excessive HTTP request volume targeting WEB-002 (Threshold: 5)."""
    return [
        _make_event(
            idx=i,
            event_type="HTTP_REQUEST",
            category="web",
            source_ip=source_ip,
            service="http",
            status="success",
            http_method="GET",
            http_path="/api/v1/data",
            response_code=200,
            time_offset_seconds=i,
        )
        for i in range(count)
    ]


def scenario_firewall_denial_burst(source_ip: str = "10.99.6.1", count: int = 6) -> List[SimpleNamespace]:
    """CV-006: Burst of firewall denied packets targeting FW-001 (Threshold: 4)."""
    return [
        _make_event(
            idx=i,
            event_type="FIREWALL",
            category="firewall",
            source_ip=source_ip,
            service=f"tcp/{8000 + i}",
            action="deny",
            status="deny",
            time_offset_seconds=i,
        )
        for i in range(count)
    ]


def scenario_application_errors(count: int = 5) -> List[SimpleNamespace]:
    """CV-007: Repeated application service errors targeting APP-001 (Threshold: 3)."""
    return [
        _make_event(
            idx=i,
            event_type="APP_ERROR",
            category="application",
            source_ip="10.99.7.1",
            service="payment_gateway",
            status="error",
            time_offset_seconds=i * 2,
        )
        for i in range(count)
    ]


def scenario_service_failures(count: int = 5) -> List[SimpleNamespace]:
    """CV-008: Repeated system service stoppage targeting SYS-001 (Threshold: 3)."""
    return [
        _make_event(
            idx=i,
            event_type="SYSTEM_EVENT",
            category="system",
            source_ip="10.99.8.1",
            service="auditd",
            status="stopped",
            time_offset_seconds=i * 2,
        )
        for i in range(count)
    ]
