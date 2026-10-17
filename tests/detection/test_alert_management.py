from src.detection.alert_lifecycle import (
    allowed_transition,
    validate_status,
)
from src.detection.risk import (
    calculate_risk_score,
    severity_from_score,
)


def test_valid_status():

    assert validate_status("NEW")
    assert validate_status("ACKNOWLEDGED")
    assert validate_status("INVESTIGATING")
    assert validate_status("RESOLVED")
    assert validate_status("FALSE_POSITIVE")


def test_invalid_status():

    assert not validate_status("INVALID_STATUS")


def test_valid_transition():

    assert allowed_transition("NEW", "ACKNOWLEDGED")
    assert allowed_transition("ACKNOWLEDGED", "INVESTIGATING")
    assert allowed_transition("INVESTIGATING", "RESOLVED")


def test_invalid_transition():

    assert not allowed_transition("NEW", "RESOLVED")
    assert not allowed_transition("RESOLVED", "NEW")


def test_risk_score():

    score = calculate_risk_score(
        severity="HIGH",
        evidence_count=5,
    )

    assert score >= 75
    assert score <= 100


def test_severity_from_score():

    assert severity_from_score(95) == "CRITICAL"
    assert severity_from_score(80) == "HIGH"
    assert severity_from_score(50) == "MEDIUM"
    assert severity_from_score(20) == "LOW"
