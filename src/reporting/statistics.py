from collections import Counter
from typing import Any, Dict, List


def calculate_event_statistics(events) -> Dict[str, Any]:
    """Calculate high-level statistics for stored events."""

    event_types = Counter()
    event_categories = Counter()
    source_ips = Counter()
    statuses = Counter()

    for event in events:
        if event.event_type:
            event_types[event.event_type] += 1

        if event.event_category:
            event_categories[event.event_category] += 1

        if event.source_ip:
            source_ips[event.source_ip] += 1

        if event.status:
            statuses[event.status] += 1

    return {
        "total_events": len(events),
        "event_types": dict(event_types),
        "event_categories": dict(event_categories),
        "top_source_ips": dict(source_ips.most_common(10)),
        "statuses": dict(statuses),
    }


def calculate_alert_statistics(alerts) -> Dict[str, Any]:
    """Calculate alert statistics."""

    severities = Counter()
    rules = Counter()
    statuses = Counter()
    risk_scores: List[float] = []

    for alert in alerts:
        if alert.severity:
            severities[alert.severity] += 1

        if alert.rule_name:
            rules[alert.rule_name] += 1

        if alert.status:
            statuses[alert.status] += 1

        if alert.risk_score is not None:
            risk_scores.append(float(alert.risk_score))

    average_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    return {
        "total_alerts": len(alerts),
        "severity_distribution": dict(severities),
        "rule_distribution": dict(rules),
        "status_distribution": dict(statuses),
        "average_risk_score": round(average_risk, 2),
    }


def calculate_incident_statistics(incidents) -> Dict[str, Any]:
    severities = Counter()
    statuses = Counter()

    for incident in incidents:
        if incident.severity:
            severities[incident.severity] += 1

        if incident.status:
            statuses[incident.status] += 1

    return {
        "total_incidents": len(incidents),
        "severity_distribution": dict(severities),
        "status_distribution": dict(statuses),
    }


def build_timeline(events) -> List[Dict[str, Any]]:
    """Create a chronological event timeline."""

    timeline = []

    for event in events:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "event_category": event.event_category,
                "source_ip": event.source_ip,
                "username": event.username,
                "status": event.status,
            }
        )

    timeline.sort(key=lambda item: item["timestamp"])
    return timeline
