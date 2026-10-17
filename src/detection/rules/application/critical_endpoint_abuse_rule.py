from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class CriticalEndpointAbuseRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="APP-003",
        rule_name="Critical Endpoint Abuse",
        category="application",
        severity="CRITICAL",
        description=(
            "Detects repeated abuse of critical endpoints such as payment, admin, or authentication APIs."
        ),
        mitre_technique="T1190",
        tags=["application", "api", "abuse"],
    )

    BAD_PATHS = ("/checkout", "/payment", "/admin", "/login", "/api")
    THRESHOLD = 6

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            route = (event.http_path or "").lower()
            if event.source_ip and any(marker in route for marker in self.BAD_PATHS):
                by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []
        for source_ip, ip_events in by_ip.items():
            if len(ip_events) >= self.THRESHOLD:
                alerts.append(
                    Alert(
                        alert_id=f"{self.rule_id}-{source_ip}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Repeated abuse of critical endpoint",
                        reason=f"{source_ip} accessed critical endpoints {len(ip_events)} times.",
                        timestamp=ip_events[0].timestamp,
                        source_ip=source_ip,
                        event_ids=[event.event_id for event in ip_events],
                        evidence=[
                            f"Endpoint accesses: {len(ip_events)}",
                            f"Critical paths: {', '.join(self.BAD_PATHS)}",
                        ],
                    )
                )
        return alerts
