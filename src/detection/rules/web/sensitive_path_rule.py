"""Detect repeated requests for sensitive administrative/configuration paths."""

from collections import defaultdict
from collections.abc import Sequence

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class SensitivePathRule(BaseDetectionRule):
    metadata = RuleMetadata(
        rule_id="WEB-005",
        rule_name="Sensitive Path Enumeration",
        category="web",
        severity="HIGH",
        description=(
            "Detects requests for commonly sensitive administrative or config paths."
        ),
        mitre_technique="T1595.003",
    )
    SENSITIVE_KEYWORDS = (
        "/wp-admin",
        "/phpmyadmin",
        "/config",
        "/backup",
        "/.env",
        "/admin",
    )
    THRESHOLD = 3

    def evaluate(self, events: Sequence[EventModel]) -> list[Alert]:
        events_by_ip: dict[str, list[EventModel]] = defaultdict(list)
        for event in events:
            path = (event.http_path or "").casefold()
            if event.source_ip and any(
                keyword in path for keyword in self.SENSITIVE_KEYWORDS
            ):
                events_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, matching in sorted(events_by_ip.items()):
            if len(matching) < self.THRESHOLD:
                continue
            matching.sort(key=lambda event: (event.timestamp, event.event_id))
            paths = sorted({event.http_path for event in matching if event.http_path})
            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Sensitive Path Enumeration",
                    reason=(
                        f"{len(matching)} requests targeted potentially sensitive "
                        f"paths from {source_ip}."
                    ),
                    timestamp=matching[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in matching],
                    evidence=[f"Paths: {', '.join(paths)}"],
                )
            )
        return alerts