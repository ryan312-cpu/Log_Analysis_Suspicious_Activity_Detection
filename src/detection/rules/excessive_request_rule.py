from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class ExcessiveRequestRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="WEB-002",
        rule_name="Excessive Request Volume",
        category="web",
        severity="MEDIUM",
        description=(
            "Detects features of unusually high HTTP request "
            "volume from a single source."
        ),
        mitre_technique="T1499",
    )

    THRESHOLD = 5

    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:

        requests_by_ip = defaultdict(list)

        for event in events:

            if (
                event.event_type == "HTTP_REQUEST"
                and event.source_ip
            ):
                requests_by_ip[
                    event.source_ip
                ].append(event)

        alerts = []

        for source_ip, request_events in (
            requests_by_ip.items()
        ):

            if len(request_events) < self.THRESHOLD:
                continue

            first = request_events[0]

            alerts.append(
                Alert(
                    alert_id=(
                        f"{self.rule_id}-"
                        f"{source_ip}"
                    ),
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title="Excessive Request Volume",
                    reason=(
                        f"{len(request_events)} HTTP "
                        f"requests originated from "
                        f"{source_ip}."
                    ),
                    timestamp=first.timestamp,
                    source_ip=source_ip,
                    event_ids=[
                        event.event_id
                        for event in request_events
                    ],
                    evidence=[
                        f"Request count: "
                        f"{len(request_events)}",
                        f"Source IP: {source_ip}",
                    ],
                )
            )

        return alerts
