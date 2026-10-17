from src.anomaly.scoring import (
    anomaly_score_from_z,
    severity_from_anomaly_score,
)


def test_high_anomaly_score():

    score = anomaly_score_from_z(3)

    assert score == 90


def test_critical_anomaly():

    severity = severity_from_anomaly_score(95)

    assert severity == "CRITICAL"


def test_low_anomaly():

    severity = severity_from_anomaly_score(20)

    assert severity == "LOW"
