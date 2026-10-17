"""Detect repeated HTTP server errors from one source."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class Repeated5xxRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="WEB-004",
        rule_name="Repeated HTTP 5xx Responses",
        category="web",
        severity="MEDIUM",
        description="Detects repeated server-side HTTP errors.",
    )
    THRESHOLD = 3

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_ip: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            if (
                event.response_code is not None
                and 500 <= event.response_code <= 599
                and event.source_ip
            ):
                events_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, matching in sorted(events_by_ip.items()):
            if len(matching) < self.THRESHOLD:
                continue
            matching.sort(key=lambda event: (event.timestamp, event.event_id))
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Repeated Server Errors",
                    reason=(
                        f"{len(matching)} HTTP 5xx responses detected from "
                        f"{source_ip}."
                    ),
                    timestamp=matching[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in matching],
                    evidence=[f"5xx count: {len(matching)}"],
                )
            )
        return alerts