from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class BruteForceRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-006",
        rule_name="Brute Force Login Pattern",
        category="authentication",
        severity="HIGH",
        description=(
            "Detects a concentrated burst of failed authentication "
            "attempts against a single account or source."
        ),
        mitre_technique="T1110",
        tags=["bruteforce", "auth"],
    )

    THRESHOLD = 5
    WINDOW_SECONDS = 300

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        failed_by_ip = defaultdict(list)
        for event in events:
            if event.event_type in {"LOGIN_FAILED", "AUTH_FAILED"} and event.source_ip:
                failed_by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in failed_by_ip.items():
            if len(ip_events) < self.THRESHOLD:
                continue

            target_users = {event.username for event in ip_events if event.username}
            first_event = ip_events[0]
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Possible brute-force sequence",
                    reason=f"{len(ip_events)} failed authentication events were observed from {source_ip}.",
                    timestamp=first_event.timestamp,
                    source_ip=source_ip,
                    username=(sorted(target_users)[0] if len(target_users) == 1 else None),
                    event_ids=[event.event_id for event in ip_events],
                    evidence=[
                        f"Failed attempts: {len(ip_events)}",
                        f"Window: {self.WINDOW_SECONDS} seconds",
                        f"Target users: {', '.join(sorted(target_users)) if target_users else 'unknown'}",
                    ],
                )
            )
        return alerts
