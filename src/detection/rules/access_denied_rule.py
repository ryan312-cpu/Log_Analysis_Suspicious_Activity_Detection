from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedAccessDeniedRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-002",
        rule_name="Repeated Access Denied",
        category="authentication",
        severity="MEDIUM",
        description=(
            "Detects repeated access-denied "
            "events from the same source."
        ),
        mitre_technique="T1110.001",
    )

    THRESHOLD = 3

    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:

        denied_by_ip = defaultdict(list)

        for event in events:

            is_denied = (
                event.status == "denied"
                or event.action == "deny"
            )

            if is_denied and event.source_ip:
                denied_by_ip[
                    event.source_ip
                ].append(event)

        alerts = []

        for source_ip, denied_events in (
            denied_by_ip.items()
        ):

            if len(denied_events) < self.THRESHOLD:
                continue

            first_event = denied_events[0]

            alerts.append(
                Alert(
                    alert_id=(
                        f"{self.rule_id}-"
                        f"{source_ip}"
                    ),
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Repeated Access Denied",
                    reason=(
                        f"{len(denied_events)} "
                        f"access-denied events detected "
                        f"from {source_ip}."
                    ),
                    timestamp=first_event.timestamp,
                    source_ip=source_ip,
                    event_ids=[
                        event.event_id
                        for event in denied_events
                    ],
                    evidence=[
                        f"Denied events: "
                        f"{len(denied_events)}",
                        f"Source IP: {source_ip}",
                    ],
                )
            )

        return alerts
