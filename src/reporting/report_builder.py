from datetime import datetime
from typing import Any, Dict

from src.reporting.statistics import (
    build_timeline,
    calculate_alert_statistics,
    calculate_event_statistics,
    calculate_incident_statistics,
)


def build_report(events, alerts, incidents) -> Dict[str, Any]:
    """Build a complete security analytics report from database objects."""

    event_stats = calculate_event_statistics(events)
    alert_stats = calculate_alert_statistics(alerts)
    incident_stats = calculate_incident_statistics(incidents)
    timeline = build_timeline(events)

    report = {
        "report_metadata": {
            "title": "Security Analytics Report",
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "Log Analysis & Suspicious Activity Detection",
        },
        "executive_summary": {
            "total_events": event_stats["total_events"],
            "total_alerts": alert_stats["total_alerts"],
            "total_incidents": incident_stats["total_incidents"],
            "average_alert_risk": alert_stats["average_risk_score"],
        },
        "event_statistics": event_stats,
        "alert_statistics": alert_stats,
        "incident_statistics": incident_stats,
        "timeline": timeline,
        "alerts": [
            {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "title": alert.title,
                "reason": alert.reason,
                "timestamp": alert.timestamp,
                "source_ip": alert.source_ip,
                "username": alert.username,
                "status": alert.status,
            }
            for alert in alerts
        ],
        "incidents": [
            {
                "incident_id": incident.incident_id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "owner": incident.owner,
                "source_ip": incident.source_ip,
                "alert_ids": incident.alert_ids,
                "evidence": incident.evidence,
                "created_at": incident.created_at,
                "updated_at": incident.updated_at,
            }
            for incident in incidents
        ],
    }

    return report
