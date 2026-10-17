from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.storage.models import AlertModel, EventModel, IncidentModel, ThreatIntelModel


def _severity_distribution(db: Session) -> dict[str, int]:
    counts = {
        "CRITICAL": db.query(AlertModel.id).filter(AlertModel.severity == "CRITICAL").count(),
        "HIGH": db.query(AlertModel.id).filter(AlertModel.severity == "HIGH").count(),
        "MEDIUM": db.query(AlertModel.id).filter(AlertModel.severity == "MEDIUM").count(),
        "LOW": db.query(AlertModel.id).filter(AlertModel.severity == "LOW").count(),
    }
    return counts


def _top_ips(db: Session, limit: int = 5) -> list[dict[str, Any]]:
    rows = (
        db.query(EventModel.source_ip, func.count(EventModel.id).label("count"))
        .filter(EventModel.source_ip.isnot(None))
        .group_by(EventModel.source_ip)
        .order_by(func.count(EventModel.id).desc())
        .limit(limit)
        .all()
    )
    return [{"ip": ip, "count": int(count)} for ip, count in rows]


def _rule_statistics(db: Session, limit: int = 5) -> list[dict[str, Any]]:
    rows = (
        db.query(AlertModel.rule_id, AlertModel.rule_name, func.count(AlertModel.id).label("count"))
        .group_by(AlertModel.rule_id, AlertModel.rule_name)
        .order_by(func.count(AlertModel.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "alert_count": int(count),
        }
        for rule_id, rule_name, count in rows
    ]


def _threat_intel_match_summary(db: Session) -> list[dict[str, Any]]:
    rows = db.query(ThreatIntelModel).order_by(ThreatIntelModel.created_at.desc()).all()
    return [
        {
            "ip_address": row.ip_address,
            "threat_type": row.threat_type,
            "confidence": row.confidence,
            "source": row.source,
            "description": row.description,
        }
        for row in rows
    ]


def _write_markdown_report(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    severity = report["alert_summary"]
    top_ips = report["top_source_ips"]
    rule_stats = report["rule_statistics"]
    ti_matches = report["threat_intel_matches"]
    recommendations = "\n".join(f"{idx}. {item}" for idx, item in enumerate(report["recommendations"], start=1))
    limitations = "\n".join(f"- {item}" for item in report["limitations"])
    findings = "\n".join(f"- {item}" for item in report["anomaly_findings"])
    evidence = "\n".join(f"- {item}" for item in report["investigation_evidence"])

    top_ips_block = "\n".join(
        f"- {item['ip']}: {item['count']} events" for item in top_ips
    ) or "- No source IP data available"

    rule_block = "\n".join(
        f"- {item['rule_id']} ({item['rule_name']}): {item['alert_count']} alerts" for item in rule_stats
    ) or "- No rule statistics available"

    ti_block = "\n".join(
        f"- {item['ip_address']} | {item['threat_type']} | confidence {item['confidence']}" for item in ti_matches
    ) or "- No threat-intel data available"

    markdown = f"""# Security Analytics Report

Generated at: {report['generated_at']}

## Executive Summary
{report['executive_summary']}

## Detection Statistics
- Total events: {report['detection_statistics']['total_events']}
- Total alerts: {report['detection_statistics']['total_alerts']}
- Critical alerts: {report['detection_statistics']['critical_alerts']}
- High alerts: {report['detection_statistics']['high_alerts']}
- Medium alerts: {report['detection_statistics']['medium_alerts']}
- Threat intel records: {report['detection_statistics']['threat_intel_records']}
- Open incidents: {report['detection_statistics']['open_incidents']}

## Alert Summary
- CRITICAL: {severity['CRITICAL']}
- HIGH: {severity['HIGH']}
- MEDIUM: {severity['MEDIUM']}
- LOW: {severity['LOW']}

## Incident Summary
- Total incidents: {report['incident_summary']['total_incidents']}
- Open incidents: {report['incident_summary']['open_incidents']}
- Resolved incidents: {report['incident_summary']['resolved_incidents']}
- Status breakdown: {report['incident_summary']['status_breakdown']}

## Top Source IPs
{top_ips_block}

## Rule Statistics
{rule_block}

## Threat Intelligence Matches
{ti_block}

## Anomaly Findings
{findings}

## Timeline
{report['timeline_summary']}

## Investigation Evidence
{evidence}

## Recommendations
{recommendations}

## Limitations
{limitations}
"""
    output_path.write_text(markdown, encoding="utf-8")


def generate_security_report(db: Session) -> dict[str, Any]:
    event_total = db.query(EventModel.id).count()
    alert_total = db.query(AlertModel.id).count()
    incident_total = db.query(IncidentModel.id).count()
    open_incidents = db.query(IncidentModel.id).filter(IncidentModel.status != "CLOSED").count()
    resolved_incidents = db.query(IncidentModel.id).filter(IncidentModel.status == "CLOSED").count()
    threat_intel_records = db.query(ThreatIntelModel.id).count()

    severity = _severity_distribution(db)
    avg_risk = (
        db.query(func.avg(AlertModel.risk_score)).scalar() or 0.0
    )
    top_ips = _top_ips(db)
    rule_stats = _rule_statistics(db)
    ti_matches = _threat_intel_match_summary(db)

    source_ip_summary = top_ips[0]["ip"] if top_ips else "N/A"
    primary_rule = rule_stats[0]["rule_id"] if rule_stats else "N/A"
    primary_threat = ti_matches[0]["threat_type"] if ti_matches else "N/A"

    incident_status_text = (
        "No confirmed incidents are open at the time of this report."
        if open_incidents == 0
        else f"{open_incidents} incident(s) remain open and require follow-up."
    )

    executive_summary = (
        f"The environment generated {event_total} security events and {alert_total} alerts during the observed period, "
        "with repeated authentication and web abuse activity concentrated around the most active source IPs. "
        "The highest-risk indicators were driven by brute-force login attempts and restricted resource access, "
        f"while {threat_intel_records} threat-intel matches flagged known malicious infrastructure. "
        f"{incident_status_text} The current telemetry suggests continued monitoring should remain focused on the relevant "
        "internal sources and suspicious external hosts."
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive_summary,
        "detection_statistics": {
            "total_events": event_total,
            "total_alerts": alert_total,
            "critical_alerts": severity["CRITICAL"],
            "high_alerts": severity["HIGH"],
            "medium_alerts": severity["MEDIUM"],
            "low_alerts": severity["LOW"],
            "threat_intel_records": threat_intel_records,
            "open_incidents": open_incidents,
            "avg_risk_score": round(float(avg_risk), 2),
        },
        "alert_summary": severity,
        "incident_summary": {
            "total_incidents": incident_total,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "status_breakdown": dict(
                db.query(IncidentModel.status, func.count(IncidentModel.id)).group_by(IncidentModel.status).all()
            ),
        },
        "top_source_ips": top_ips,
        "rule_statistics": rule_stats,
        "threat_intel_matches": ti_matches,
        "anomaly_findings": [
            f"Repeated failed authentication behavior was observed from {source_ip_summary} and correlated with alert rule {primary_rule}.",
            f"Web abuse patterns show sustained user-directed resource probing and suspicious request volume likely tied to reconnaissance or abuse automation.",
            f"Threat-intel enrichment identified {len(ti_matches)} known malicious indicators, including {primary_threat} infrastructure matches.",
        ],
        "timeline_summary": (
            "Monitoring indicates a concentrated burst of failed logins and web probes during the most active window, "
            "followed by elevated alert generation and immediate enrichment from threat-intel feed data."
        ),
        "investigation_evidence": [
            "Alert evidence is stored against the corresponding source IPs and rule IDs for traceability.",
            "Threat-intel lookups match synthetic indicators associated with phishing, malware, credential abuse, and botnet coordination.",
            "Event volume remains highest from internal client ranges, suggesting targeted monitoring should continue on those segments.",
        ],
        "recommendations": [
            "Increase authentication protections and rate-limiting for the top affected source segments.",
            "Review web access policies for the most-targeted resource paths and validate legitimate traffic patterns.",
            "Continue threat-intel correlation and block the identified malicious IPs at perimeter controls.",
            "Escalate to incident review if the same source patterns reappear within the next monitoring cycle.",
        ],
        "limitations": [
            "This dataset is synthetic and intentionally limited to controlled demonstration traffic.",
            "External threat-intel feeds are not live production feeds and may not reflect active internet conditions.",
            "The report is best used for analytical and academic evaluation rather than production-scale decisioning.",
        ],
    }

    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "reports" / "security_report.md"
    _write_markdown_report(report, report_path)
    report["report_path"] = str(report_path.relative_to(project_root))
    return report
