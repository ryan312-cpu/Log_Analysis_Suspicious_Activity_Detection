from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedApplicationErrorsRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="APP-001",
        rule_name="Repeated Application Errors",
        category="application",
        severity="MEDIUM",
        description=(
            "Detects repeated application-level errors that indicate service instability or abuse."
        ),
        mitre_technique="T1488",
        tags=["application", "errors"],
    )

    THRESHOLD = 5

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_service = defaultdict(list)
        for event in events:
            if event.service and event.status in {"error", "failed", "500"}:
                by_service[event.service].append(event)

        alerts: List[Alert] = []
        for service, service_events in by_service.items():
            if len(service_events) < self.THRESHOLD:
                continue

            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{service}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Application error burst",
                    reason=f"Service {service} generated {len(service_events)} failures.",
                    timestamp=service_events[0].timestamp,
                    source_ip=service_events[0].source_ip,
                    event_ids=[event.event_id for event in service_events],
                    evidence=[
                        f"Errors: {len(service_events)}",
                        f"Service: {service}",
                    ],
                )
            )
        return alerts
