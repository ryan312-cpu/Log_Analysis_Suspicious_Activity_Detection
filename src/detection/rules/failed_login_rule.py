from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class MultipleFailedLoginRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-001",
        rule_name="Multiple Failed Logins",
        category="authentication",
        severity="HIGH",
        description=(
            "Detects repeated failed login attempts "
            "from the same source."
        ),
        mitre_technique="T1110",
    )

    THRESHOLD = 5

    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:

        failed_by_ip = defaultdict(list)

        for event in events:

            if (
                event.event_type == "LOGIN_FAILED"
                and event.source_ip
            ):
                failed_by_ip[
                    event.source_ip
                ].append(event)

        alerts = []

        for source_ip, failed_events in (
            failed_by_ip.items()
        ):

            if len(failed_events) < self.THRESHOLD:
                continue

            first_event = failed_events[0]

            usernames = sorted(
                {
                    event.username
                    for event in failed_events
                    if event.username
                }
            )

            alert = Alert(
                alert_id=(
                    f"{self.rule_id}-"
                    f"{source_ip}"
                ),
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                title="Possible Brute-Force Activity",
                reason=(
                    f"{len(failed_events)} failed "
                    f"login attempts detected from "
                    f"{source_ip}."
                ),
                timestamp=first_event.timestamp,
                source_ip=source_ip,
                username=(
                    usernames[0]
                    if len(usernames) == 1
                    else None
                ),
                event_ids=[
                    event.event_id
                    for event in failed_events
                ],
                evidence=[
                    f"Failed attempts: "
                    f"{len(failed_events)}",
                    f"Source IP: {source_ip}",
                    f"Target users: "
                    f"{', '.join(usernames)}",
                ],
            )

            alerts.append(alert)

        return alerts
