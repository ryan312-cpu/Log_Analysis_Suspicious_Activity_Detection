from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class CredentialStuffingRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-007",
        rule_name="Credential Stuffing",
        category="authentication",
        severity="HIGH",
        description=(
            "Detects a single IP attempting many usernames using repeated "
            "failed logins in a short time window."
        ),
        mitre_technique="T1110.004",
        tags=["credential-stuffing", "auth"],
    )

    USER_THRESHOLD = 5
    WINDOW_SECONDS = 240

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if event.event_type in {"LOGIN_FAILED", "AUTH_FAILED"} and event.source_ip and event.username:
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            unique_users = {event.username for event in ip_events}
            if len(unique_users) < self.USER_THRESHOLD:
                continue

            first_event = ip_events[0]
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Credential stuffing activity",
                    reason=f"{source_ip} targeted {len(unique_users)} distinct usernames within a short window.",
                    timestamp=first_event.timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in ip_events],
                    evidence=[
                        f"Distinct usernames: {len(unique_users)}",
                        f"Users: {', '.join(sorted(unique_users))}",
                        f"Window: {self.WINDOW_SECONDS} seconds",
                    ],
                )
            )
        return alerts
