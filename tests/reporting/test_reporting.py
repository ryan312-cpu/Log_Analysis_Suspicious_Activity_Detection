from src.reporting.statistics import (
    calculate_alert_statistics,
    calculate_event_statistics,
    calculate_incident_statistics,
)


class MockEvent:
    def __init__(self, event_type, event_category, source_ip, status):
        self.event_type = event_type
        self.event_category = event_category
        self.source_ip = source_ip
        self.status = status


class MockAlert:
    def __init__(self, rule_name, severity, status, risk_score):
        self.rule_name = rule_name
        self.severity = severity
        self.status = status
        self.risk_score = risk_score


class MockIncident:
    def __init__(self, severity, status):
        self.severity = severity
        self.status = status


def test_event_statistics():
    events = [
        MockEvent("LOGIN_FAILED", "authentication", "192.168.10.55", "failure"),
        MockEvent("LOGIN_SUCCESS", "authentication", "192.168.10.55", "success"),
    ]

    result = calculate_event_statistics(events)

    assert result["total_events"] == 2
    assert result["top_source_ips"]["192.168.10.55"] == 2


def test_alert_statistics():
    alerts = [
        MockAlert("Multiple Failed Logins", "HIGH", "NEW", 85),
        MockAlert("Password Spraying", "CRITICAL", "NEW", 95),
    ]

    result = calculate_alert_statistics(alerts)

    assert result["total_alerts"] == 2
    assert result["severity_distribution"]["HIGH"] == 1
    assert result["severity_distribution"]["CRITICAL"] == 1


def test_incident_statistics():
    incidents = [
        MockIncident("HIGH", "OPEN"),
        MockIncident("CRITICAL", "INVESTIGATING"),
    ]

    result = calculate_incident_statistics(incidents)

    assert result["total_incidents"] == 2
    assert result["status_distribution"]["OPEN"] == 1
