from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class GeoAnomalyRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="FW-003",
        rule_name="Geo Anomaly",
        category="firewall",
        severity="MEDIUM",
        description=(
            "Flags suspicious access from external or unusual source networks that trigger repeated blocks."
        ),
        mitre_technique="T1583",
        tags=["firewall", "network"],
    )

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if event.source_ip and (event.action == "deny" or event.status == "denied"):
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            if len(ip_events) >= 3 and not source_ip.startswith(("10.", "192.168.", "172.")):
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{source_ip}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="External source exhibiting blocked access behavior",
                        reason=f"{source_ip} generated repeated denied events from outside the trusted internal ranges.",
                        timestamp=ip_events[0].timestamp,
                        source_ip=source_ip,
                        event_ids=[event.event_id for event in ip_events],
                        evidence=[
                            f"Denied events: {len(ip_events)}",
                            "Source is external to private ranges",
                        ],
                    )
                )
        return alerts
