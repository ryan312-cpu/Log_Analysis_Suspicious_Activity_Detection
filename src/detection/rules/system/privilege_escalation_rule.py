from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class PrivilegeEscalationRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="SYS-002",
        rule_name="Privilege Escalation",
        category="system",
        severity="CRITICAL",
        description=(
            "Detects privilege changes or escalation actions that could indicate account takeover or misuse."
        ),
        mitre_technique="T1548",
        tags=["system", "privilege"],
    )

    ESCALATION_ACTIONS = ("sudo", "su", "setuid", "chmod", "privilege_change", "elevate")

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        alerts: List[Alert] = []
        for event in events:
            action = (event.action or "").lower()
            if any(marker in action for marker in self.ESCALATION_ACTIONS) or event.event_type == "PRIVILEGE_CHANGE":
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{event.event_id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Privilege escalation action observed",
                        reason=f"{event.username or event.source_ip or 'unknown actor'} performed a privilege modification.",
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username=event.username,
                        event_ids=[event.event_id],
                        evidence=[
                            f"Action: {event.action}",
                            "Privileged configuration or user context changed",
                        ],
                    )
                )
        return alerts
