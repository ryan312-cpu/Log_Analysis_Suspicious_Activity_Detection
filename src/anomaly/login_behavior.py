from collections import defaultdict
from datetime import datetime
from uuid import uuid4

from src.anomaly.models import AnomalyFinding


def detect_unusual_login_hours(
    events,
    minimum_history: int = 3,
):
    user_hours = defaultdict(list)

    for event in events:

        if event.event_type != "LOGIN_SUCCESS":
            continue

        if not event.username:
            continue

        timestamp = datetime.fromisoformat(event.timestamp)
        user_hours[event.username].append(timestamp.hour)

    findings = []

    for username, hours in user_hours.items():

        if len(hours) < minimum_history:
            continue

        normal_hours = set(hours)

        for event in events:

            if event.event_type != "LOGIN_SUCCESS":
                continue

            if event.username != username:
                continue

            timestamp = datetime.fromisoformat(event.timestamp)

            if timestamp.hour in normal_hours:
                continue

            findings.append(
                AnomalyFinding(
                    anomaly_id=f"ANOM-{uuid4().hex[:12]}",
                    anomaly_type="UNUSUAL_LOGIN_HOUR",
                    severity="MEDIUM",
                    score=60.0,
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=username,
                    reason=(
                        f"User {username} authenticated at {timestamp.hour:02d}:00, "
                        f"outside previously observed login hours."
                    ),
                    evidence=[
                        f"Observed login hours: {sorted(normal_hours)}",
                        f"Observed hour: {timestamp.hour}",
                    ],
                )
            )

    return findings
