"""Detect repeated failures or stops reported for the same system service."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedServiceFailureRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="SYS-001",
        rule_name="Repeated Service Failures",
        category="system",
        severity="HIGH",
        description="Detects repeated service failures in system logs.",
    )
    THRESHOLD = 3
    FAILURE_STATES = {"error", "failed", "failure", "stopped"}

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_service: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            status = (event.status or "").strip().casefold()
            if (
                event.event_type in {"SYSTEM", "SYSTEM_EVENT"}
                and status in self.FAILURE_STATES
                and event.service
            ):
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
                    title="Repeated Service Failures",
                    reason=f"Service {service} reported {len(matching)} failures.",
                    timestamp=matching[0].timestamp,
                    event_ids=[event.event_id for event in matching],
                    evidence=[
                        f"Service: {service}",
                        f"Failure count: {len(matching)}",
                    ],
                )
            )
        return alerts