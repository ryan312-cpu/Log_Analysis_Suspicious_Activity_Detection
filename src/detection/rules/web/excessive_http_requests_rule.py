from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class ExcessiveHttpRequestsRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="WEB-003",
        rule_name="Excessive HTTP Requests",
        category="web",
        severity="MEDIUM",
        description=(
            "Detects a client or source generating an abnormal volume of web requests."
        ),
        mitre_technique="T1498",
        tags=["web", "dos"],
    )

    THRESHOLD = 100

    def evaluate(self, events: List[EventModel]) -> List[Alert]:
        by_ip = defaultdict(list)
        for event in events:
            if event.source_ip and (event.event_type in {"HTTP_REQUEST", "WEB_REQUEST"} or event.http_path):
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
                    title="High-volume web request burst",
                    reason=f"{source_ip} generated {len(ip_events)} HTTP requests.",
                    timestamp=ip_events[0].timestamp,
                    source_ip=source_ip,
                    event_ids=[event.event_id for event in ip_events],
                    evidence=[
                        f"Request count: {len(ip_events)}",
                        f"Threshold: {self.THRESHOLD}",
                    ],
                )
            )
        return alerts
