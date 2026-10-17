"""Detect an account successfully used from several source IPs."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class MultipleSourceLoginRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="AUTH-007",
        rule_name="Multiple Source Login",
        category="authentication",
        severity="MEDIUM",
        description=(
            "Detects an account receiving successful logins from multiple sources."
        ),
    )
    SOURCE_THRESHOLD = 3

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_user: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            if (
                event.event_type == "LOGIN_SUCCESS"
                and event.username
                and event.source_ip
            ):
                events_by_user[event.username].append(event)

        alerts = []
        for username, user_events in sorted(events_by_user.items()):
            sources = sorted({event.source_ip for event in user_events})
            if len(sources) < self.SOURCE_THRESHOLD:
                continue
            user_events.sort(
                key=lambda event: (event.timestamp, event.event_id)
            )
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{username}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Account Used From Multiple Sources",
                    reason=(
                        f"Account {username} had successful logins from "
                        f"{len(sources)} different source IPs."
                    ),
                    timestamp=user_events[0].timestamp,
                    username=username,
                    event_ids=[event.event_id for event in user_events],
                    evidence=[f"Source IPs: {', '.join(sources)}"],
                )
            )
        return alerts