from datetime import datetime
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule
from src.storage.models import EventModel


class UnusualLoginTimeRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-003",
        rule_name="Unusual Login Time",
        category="authentication",
        severity="MEDIUM",
        description=(
            "Detects successful logins outside "
            "the defined normal login window."
        ),
        mitre_technique="T1078",
    )

    START_HOUR = 6
    END_HOUR = 22

    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:

        alerts = []

        for event in events:

            if event.event_type != "LOGIN_SUCCESS":
                continue

            try:
                timestamp = datetime.fromisoformat(
                    event.timestamp
                )
            except ValueError:
                continue

            hour = timestamp.hour

            if (
                hour < self.START_HOUR
                or hour >= self.END_HOUR
            ):

                alerts.append(
                    Alert(
                        alert_id=(
                            f"{self.rule_id}-"
                            f"{event.event_id}"
                        ),
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Unusual Login Time",
                        reason=(
                            f"Successful login occurred "
                            f"outside the normal login "
                            f"window "
                            f"({self.START_HOUR:02d}:00-"
                            f"{self.END_HOUR:02d}:00)."
                        ),
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        username=event.username,
                        event_ids=[
                            event.event_id
                        ],
                        evidence=[
                            f"Login time: "
                            f"{event.timestamp}",
                            f"Username: "
                            f"{event.username or 'unknown'}",
                            f"Source IP: "
                            f"{event.source_ip or 'unknown'}",
                        ],
                    )
                )

        return alerts
