from collections import defaultdict

from src.detection.correlation.correlator import parse_timestamp
from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule


class PasswordSprayingRule(BaseDetectionRule):

    metadata = RuleMetadata(
        rule_id="AUTH-005",
        rule_name="Password Spraying",
        category="authentication",
        severity="HIGH",
        description=(
            "Detects failed authentication attempts "
            "against multiple usernames from one source."
        ),
        mitre_technique="T1110.003",
    )

    USER_THRESHOLD = 4
    WINDOW_SECONDS = 120

    def evaluate(self, events):

        events_by_ip = defaultdict(list)

        for event in events:

            if (
                event.event_type == "LOGIN_FAILED"
                and event.source_ip
                and event.username
            ):
                events_by_ip[
                    event.source_ip
                ].append(event)

        alerts = []

        for source_ip, ip_events in (
            events_by_ip.items()
        ):

            ip_events.sort(
                key=lambda event: parse_timestamp(
                    event.timestamp
                )
            )

            for event in ip_events:

                start = parse_timestamp(
                    event.timestamp
                )

                users = set()

                evidence_events = []

                for candidate in ip_events:

                    candidate_time = (
                        parse_timestamp(
                            candidate.timestamp
                        )
                    )

                    difference = (
                        candidate_time - start
                    ).total_seconds()

                    if (
                        0 <= difference
                        <= self.WINDOW_SECONDS
                    ):

                        users.add(
                            candidate.username
                        )

                        evidence_events.append(
                            candidate
                        )

                if len(users) >= self.USER_THRESHOLD:

                    alerts.append(
                        Alert(
                            alert_id=(
                                f"{self.rule_id}-"
                                f"{source_ip}-"
                                f"{event.event_id}"
                            ),
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.severity,
                            title=(
                                "Possible Password "
                                "Spraying Activity"
                            ),
                            reason=(
                                f"{source_ip} attempted "
                                f"authentication against "
                                f"{len(users)} different "
                                f"users within "
                                f"{self.WINDOW_SECONDS} "
                                f"seconds."
                            ),
                            timestamp=event.timestamp,
                            source_ip=source_ip,
                            event_ids=[
                                e.event_id
                                for e in evidence_events
                            ],
                            evidence=[
                                f"Unique users: "
                                f"{len(users)}",
                                f"Users: "
                                f"{', '.join(sorted(users))}",
                                f"Window: "
                                f"{self.WINDOW_SECONDS} "
                                f"seconds",
                            ],
                        )
                    )

                    break

        return alerts
