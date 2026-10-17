from collections import defaultdict
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class RestrictedResourceRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="WEB-001",
        rule_name="Restricted Resource Access",
        category="web",
        severity="HIGH",
        description=(
            "Detects repeated attempts to access "
            "restricted web resources."
        ),
        mitre_technique="T1083",
    )

    THRESHOLD = 3

    RESTRICTED_PATHS = (
        "/admin",
        "/admin/",
        "/admin/config",
        "/admin/users",
        "/admin/database",
        "/admin/secrets",
    )

    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:

        attempts = defaultdict(list)

        for event in events:

            if not event.source_ip:
                continue

            path = event.http_path or ""

            if (
                path in self.RESTRICTED_PATHS
                and event.response_code
                and event.response_code in {
                    401,
                    403,
                }
            ):
                attempts[
                    event.source_ip
                ].append(event)

        alerts = []

        for source_ip, events_list in attempts.items():

            if len(events_list) < self.THRESHOLD:
                continue

            first = events_list[0]

            paths = sorted(
                {
                    event.http_path
                    for event in events_list
                    if event.http_path
                }
            )

            alerts.append(
                Alert(
                    alert_id=(
                        f"{self.rule_id}-"
                        f"{source_ip}"
                    ),
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    title=(
                        "Restricted Resource "
                        "Access Attempts"
                    ),
                    reason=(
                        f"{len(events_list)} attempts "
                        f"to restricted resources "
                        f"were detected."
                    ),
                    timestamp=first.timestamp,
                    source_ip=source_ip,
                    event_ids=[
                        event.event_id
                        for event in events_list
                    ],
                    evidence=[
                        f"Source IP: {source_ip}",
                        f"Attempt count: "
                        f"{len(events_list)}",
                        f"Paths: {', '.join(paths)}",
                    ],
                )
            )

        return alerts
