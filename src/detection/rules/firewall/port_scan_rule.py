from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class PortScanRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="FW-002",
        rule_name="Port Scan Activity",
        category="firewall",
        severity="HIGH",
        description=(
            "Detects a single source probing a broad range of destination ports or services."
        ),
        mitre_technique="T1046",
        tags=["firewall", "recon"],
    )

    PORT_THRESHOLD = 8

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(set)
        for event in events:
            if event.source_ip and event.destination_ip:
                by_ip[event.source_ip].add(event.destination_ip)

        alerts: List[Alert] = []
        for source_ip, targets in by_ip.items():
            if len(targets) >= self.PORT_THRESHOLD:
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{source_ip}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Port scan against multiple targets",
                        reason=f"{source_ip} contacted {len(targets)} destinations in a short period.",
                        timestamp=next(iter(sorted({event.timestamp for event in events if event.source_ip == source_ip})), "unknown"),
                        source_ip=source_ip,
                        event_ids=[event.event_id for event in events if event.source_ip == source_ip],
                        evidence=[
                            f"Distinct targets: {len(targets)}",
                            f"Threshold: {self.PORT_THRESHOLD}",
                        ],
                    )
                )
        return alerts
