"""Detect repeated firewall denies from one source."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedFirewallDeniedRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="FW-001",
        rule_name="Repeated Firewall Denials",
        category="firewall",
        severity="HIGH",
        description="Detects repeated firewall deny events from a source.",
        mitre_technique="T1046",
    )
    THRESHOLD = 4
    DENY_VALUES = {"deny", "denied", "block", "blocked"}

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_ip: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            action = (event.action or "").strip().casefold()
            status = (event.status or "").strip().casefold()
            if event.source_ip and (
                action in self.DENY_VALUES or status in self.DENY_VALUES
            ):
                events_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, matching in sorted(events_by_ip.items()):
            if len(matching) < self.THRESHOLD:
                continue
            matching.sort(key=lambda event: (event.timestamp, event.event_id))
            services = sorted({event.service for event in matching if event.service})
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Repeated Firewall Denials",
                    reason=(
                        f"{len(matching)} firewall deny events detected from "
                        f"{source_ip}."
                    ),
                    timestamp=matching[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in matching],
                    evidence=[
                        f"Denied events: {len(matching)}",
                        f"Services: {', '.join(services)}",
                    ],
                )
            )
        return alerts