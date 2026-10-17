from src.incidents.lifecycle import (
    allowed_incident_transition,
    validate_incident_severity,
    validate_incident_status,
)


def test_valid_status():
    assert validate_incident_status("OPEN")


def test_invalid_status():
    assert not validate_incident_status("INVALID")


def test_valid_severity():
    assert validate_incident_severity("HIGH")


def test_valid_transition():
    assert allowed_incident_transition("OPEN", "TRIAGING")


def test_invalid_transition():
    assert not allowed_incident_transition("OPEN", "RESOLVED")
