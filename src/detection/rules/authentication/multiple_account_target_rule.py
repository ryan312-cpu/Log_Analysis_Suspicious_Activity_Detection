"""Detect one source targeting many accounts in a short period."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.correlation.correlator import (
    events_within_window,
    parse_timestamp,
)
from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class MultipleAccountTargetRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="AUTH-006",
        rule_name="Multiple Account Targeting",
        category="authentication",
        severity="HIGH",
        description=(
            "Detects one source attempting to authenticate against many accounts."
        ),
        mitre_technique="T1110.003",
    )
    USER_THRESHOLD = 4
    WINDOW_SECONDS = 120

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_ip: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            if (
                event.event_category == "authentication"
                and event.event_type in {"LOGIN_FAILED", "LOGIN_SUCCESS"}
                and event.source_ip
                and event.username
            ):
                events_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, ip_events in sorted(events_by_ip.items()):
            ip_events.sort(
                key=lambda event: (parse_timestamp(event.timestamp), event.event_id)
            )
            for start_event in ip_events:
                window_events = events_within_window(
                    ip_events,
                    parse_timestamp(start_event.timestamp),
                    self.WINDOW_SECONDS,
                )
                users = sorted(
                    {event.username for event in window_events if event.username}
                )
                if len(users) < self.USER_THRESHOLD:
                    continue

                alerts.append(
                    Alert(
                        alert_id=(
                            f"{self.rule_id}-{source_ip}-"
                            f"{start_event.event_id}"
                        ),
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Multiple Accounts Targeted",
                        reason=(
                            f"{source_ip} attempted authentication against "
                            f"{len(users)} accounts within {self.WINDOW_SECONDS} seconds."
                        ),
                        timestamp=start_event.timestamp,
                        source_ip=source_ip,
                        event_ids=[event.event_id for event in window_events],
                        evidence=[
                            f"Accounts targeted: {', '.join(users)}",
                            f"Account count: {len(users)}",
                        ],
                    )
                )
                break
        return alerts