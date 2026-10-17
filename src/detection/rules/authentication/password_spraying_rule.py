from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class AuthenticationPasswordSprayingRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-008",
        rule_name="Password Spraying",
        category="authentication",
        severity="MEDIUM",
        description=(
            "Detects one source attempting the same password against many accounts."
        ),
        mitre_technique="T1110.003",
        tags=["spray", "auth"],
    )

    USER_THRESHOLD = 3

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if event.event_type in {"LOGIN_FAILED", "AUTH_FAILED"} and event.source_ip and event.username:
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            users = {event.username for event in ip_events}
            if len(users) < self.USER_THRESHOLD:
                continue

            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Potential password spraying attack",
                    reason=f"{source_ip} failed authentication for {len(users)} accounts.",
                    timestamp=ip_events[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in ip_events],
                    evidence=[
                        f"Targeted accounts: {len(users)}",
                        f"Accounts: {', '.join(sorted(users))}",
                    ],
                )
            )
        return alerts
