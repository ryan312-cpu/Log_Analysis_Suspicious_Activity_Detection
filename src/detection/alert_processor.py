from src.detection.risk import (
    calculate_risk_score,
    severity_from_score,
)


def calculate_alert_risk(alert):

    evidence_count = len(alert.event_ids)
    correlation_bonus = 5 if len(alert.event_ids) >= 5 else 0

    score = calculate_risk_score(
        severity=alert.severity,
        evidence_count=evidence_count,
        correlation_bonus=correlation_bonus,
    )

    return score


def process_alert(alert):

    score = calculate_alert_risk(alert)
    calculated_severity = severity_from_score(score)

    return {
        "alert": alert,
        "risk_score": score,
        "calculated_severity": calculated_severity,
    }
