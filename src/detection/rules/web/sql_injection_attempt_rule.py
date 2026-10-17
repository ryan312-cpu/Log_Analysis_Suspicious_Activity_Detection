from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class SqlInjectionAttemptRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="WEB-004",
        rule_name="SQL Injection Attempt",
        category="web",
        severity="CRITICAL",
        description=(
            "Detects suspicious request patterns associated with SQL injection attempts."
        ),
        mitre_technique="T1190",
        tags=["sqli", "web"],
    )

    SUSPICIOUS_PATTERNS = (
        "union select",
        "or 1=1",
        "sleep(",
        "benchmark(",
        "information_schema",
        "--",
    )

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        alerts: List[Alert] = []
        for event in events:
            payload = " ".join(filter(None, [event.http_path, event.raw_log, event.action])).lower()
            if not payload:
                continue

            if any(pattern in payload for pattern in self.SUSPICIOUS_PATTERNS):
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{event.event_id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="SQL injection pattern detected",
                        reason=f"Suspicious request content was observed for {event.source_ip or 'unknown source'}.",
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        event_ids=[event.event_id],
                        evidence=[
                            f"Payload: {payload[:200]}",
                            "Matches SQL injection signature",
                        ],
                    )
                )
        return alerts
