from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class ServiceFailureRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="SYS-001",
        rule_name="Service Failure",
        category="system",
        severity="HIGH",
        description=(
            "Detects repeated system or service failures that may indicate an outage or compromise."
        ),
        mitre_technique="T1489",
        tags=["system", "service"],
    )

    THRESHOLD = 3

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_service = defaultdict(list)
        for event in events:
            if event.service and (event.status in {"error", "failed", "down"} or event.action in {"restart", "stop"}):
                by_service[event.service].append(event)

        alerts: List[Alert] = []
        for service, service_events in by_service.items():
            if len(service_events) >= self.THRESHOLD:
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{service}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Multiple service failures observed",
                        reason=f"Service {service} failed {len(service_events)} times.",
                        timestamp=service_events[0].timestamp,
                        source_ip=service_events[0].source_ip,
                        event_ids=[event.event_id for event in service_events],
                        evidence=[
                            f"Failure count: {len(service_events)}",
                            f"Service: {service}",
                        ],
                    )
                )
        return alerts
