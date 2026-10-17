from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RepeatedDeniedConnectionsRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="FW-001",
        rule_name="Repeated Denied Connections",
        category="firewall",
        severity="MEDIUM",
        description=(
            "Detects repeated connection denials from a single source or to a protected target."
        ),
        mitre_technique="T1046",
        tags=["firewall", "denied"],
    )

    THRESHOLD = 5

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if (event.action == "deny" or event.status == "denied") and event.source_ip:
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            if len(ip_events) < self.THRESHOLD:
                continue

            alerts.append(
                Alert(
                    alert_id=f"{self.rule_id}-{source_ip}",
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Repeated connection denial",
                    reason=f"{source_ip} triggered {len(ip_events)} denied connections.",
                    timestamp=ip_events[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in ip_events],
                    evidence=[
                        f"Denied events: {len(ip_events)}",
                        f"Threshold: {self.THRESHOLD}",
                    ],
                )
            )
        return alerts
