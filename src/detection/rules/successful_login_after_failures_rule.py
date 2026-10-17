from collections import defaultdict

from src.detection.correlation.correlator import parse_timestamp
from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule


class SuccessfulLoginAfterFailuresRule(
    BaseDetectionRule
):

    metadata = RuleMetadata(
        rule_id="AUTH-004",
        rule_name="Successful Login After Failures",
        category="authentication",
        severity="CRITICAL",
        description=(
            "Detects a successful login shortly after "
            "multiple failed login attempts."
        ),
        mitre_technique="T1110",
    )

    FAILURE_THRESHOLD = 3
    WINDOW_SECONDS = 120

    def evaluate(self, events):

        events_by_ip = defaultdict(list)

        for event in events:

            if event.source_ip:
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

                if event.event_type != "LOGIN_SUCCESS":
                    continue

                success_time = parse_timestamp(
                    event.timestamp
                )

                previous_events = [
                    e
                    for e in ip_events
                    if parse_timestamp(
                        e.timestamp
                    ) <= success_time
                ]

                window_start = (
                    success_time.timestamp()
                    - self.WINDOW_SECONDS
                )

                recent_failures = [
                    e
                    for e in previous_events
                    if (
                        e.event_type
                        == "LOGIN_FAILED"
                        and parse_timestamp(
                            e.timestamp
                        ).timestamp()
                        >= window_start
                    )
                ]

                if (
                    len(recent_failures)
                    < self.FAILURE_THRESHOLD
                ):
                    continue

                event_ids = [
                    e.event_id
                    for e in recent_failures
                ]

                event_ids.append(
                    event.event_id
                )

                alerts.append(
                    Alert(
                        alert_id=(
                            f"{self.rule_id}-"
                            f"{event.event_id}"
                        ),
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title=(
                            "Successful Login After "
                            "Repeated Failures"
                        ),
                        reason=(
                            f"{len(recent_failures)} "
                            f"failed login attempts were "
                            f"followed by a successful "
                            f"login from {source_ip} "
                            f"within "
                            f"{self.WINDOW_SECONDS} seconds."
                        ),
                        timestamp=event.timestamp,
                        source_ip=source_ip,
                        username=event.username,
                        event_ids=event_ids,
                        evidence=[
                            f"Failed attempts: "
                            f"{len(recent_failures)}",
                            "Followed by successful login",
                            f"Window: "
                            f"{self.WINDOW_SECONDS} seconds",
                        ],
                    )
                )

        return alerts
