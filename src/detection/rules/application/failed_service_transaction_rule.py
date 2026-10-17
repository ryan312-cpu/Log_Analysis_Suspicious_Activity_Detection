from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class FailedServiceTransactionRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="APP-002",
        rule_name="Failed Service Transaction",
        category="application",
        severity="HIGH",
        description=(
            "Detects repeated failed business or service transactions within a short time."
        ),
        mitre_technique="T1650",
        tags=["application", "transactions"],
    )

    THRESHOLD = 4

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_service = defaultdict(list)
        for event in events:
            if event.service and event.action in {"transaction", "purchase", "checkout", "transfer"} and event.status in {"failed", "error"}:
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
                        title="Repeated failed transactional work",
                        reason=f"Service {service} saw {len(service_events)} failed transactions.",
                        timestamp=service_events[0].timestamp,
                        source_ip=service_events[0].source_ip,
                        event_ids=[event.event_id for event in service_events],
                        evidence=[
                            f"Failed transactions: {len(service_events)}",
                            f"Service: {service}",
                        ],
                    )
                )
        return alerts
