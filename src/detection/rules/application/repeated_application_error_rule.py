"""Detect repeated errors reported by the same application service."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedApplicationErrorRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="APP-001",
        rule_name="Repeated Application Errors",
        category="application",
        severity="MEDIUM",
        description="Detects repeated application errors from the same service.",
    )
    THRESHOLD = 3
    ERROR_EVENT_TYPES = {"APP_ERROR", "API_ERROR"}

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_service: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            if event.event_type in self.ERROR_EVENT_TYPES and event.service:
                events_by_service[event.service].append(event)

        alerts = []
        for service, matching in sorted(events_by_service.items()):
            if len(matching) < self.THRESHOLD:
                continue
            matching.sort(key=lambda event: (event.timestamp, event.event_id))
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{service}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Repeated Application Errors",
                    reason=(
                        f"{len(matching)} application errors detected for "
                        f"service {service}."
                    ),
                    timestamp=matching[0].timestamp,
                    event_ids=[event.event_id for event in matching],
                    evidence=[
                        f"Service: {service}",
                        f"Error count: {len(matching)}",
                    ],
                )
            )
        return alerts