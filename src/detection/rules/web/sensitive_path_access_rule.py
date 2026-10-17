from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class SensitivePathAccessRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="WEB-005",
        rule_name="Sensitive Path Access",
        category="web",
        severity="HIGH",
        description=(
            "Detects access to administrative, configuration, or sensitive web resources."
        ),
        mitre_technique="T1190",
        tags=["web", "sensitive-path"],
    )

    SENSITIVE_PATHS = ("/admin", "/login", "/wp-admin", "/.env", "/config", "/backup")

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        alerts: List[Alert] = []
        for event in events:
            path = (event.http_path or "").lower()
            if any(marker in path for marker in self.SENSITIVE_PATHS):
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{event.event_id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Sensitive path accessed",
                        reason=f"{event.source_ip or 'unknown source'} requested a sensitive web path.",
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        event_ids=[event.event_id],
                        evidence=[
                            f"Path: {event.http_path}",
                            "Access to privileged resource",
                        ],
                    )
                )
        return alerts
