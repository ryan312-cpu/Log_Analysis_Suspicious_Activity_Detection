from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class HostReconnaissanceRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="SYS-003",
        rule_name="Host Reconnaissance",
        category="system",
        severity="MEDIUM",
        description=(
            "Detects scans or repeated probes designed to enumerate host services or paths."
        ),
        mitre_technique="T1595",
        tags=["system", "recon"],
    )

    THRESHOLD = 6

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if event.source_ip and (event.event_type in {"PORT_SCAN", "NETWORK_PROBE", "SYSTEM_PROBE"} or event.service):
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            unique_services = {event.service for event in ip_events if event.service}
            if len(unique_services) >= self.THRESHOLD:
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{source_ip}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Host reconnaissance pattern",
                        reason=f"{source_ip} probed {len(unique_services)} services or endpoints.",
                        timestamp=ip_events[0].timestamp,
                        source_ip=source_ip,
                        event_ids=[event.event_id for event in ip_events],
                        evidence=[
                            f"Distinct services: {len(unique_services)}",
                            f"Services: {', '.join(sorted(unique_services))}",
                        ],
                    )
                )
        return alerts
