from collections import defaultdict
from datetime import datetime
from uuid import uuid4

from src.anomaly.models import AnomalyFinding
from src.anomaly.scoring import (
    anomaly_score_from_z,
    calculate_z_score,
    severity_from_anomaly_score,
)


def detect_source_volume_anomalies(
    events,
    baseline,
):
    findings = []

    grouped = defaultdict(list)

    for event in events:

        if not event.source_ip:
            continue

        grouped[event.source_ip].append(event)

    for source_ip, source_events in grouped.items():

        if source_ip not in baseline:
            continue

        hourly_events = defaultdict(list)

        for event in source_events:

            timestamp = datetime.fromisoformat(event.timestamp)
            hour_key = timestamp.strftime("%Y-%m-%d %H")
            hourly_events[hour_key].append(event)

        profile = baseline[source_ip]

        for hour_key, hour_events in hourly_events.items():

            count = len(hour_events)

            z_score = calculate_z_score(
                count,
                profile["mean"],
                profile["stddev"],
            )

            score = anomaly_score_from_z(z_score)

            if score < 75:
                continue

            severity = severity_from_anomaly_score(score)
            representative = hour_events[0]

            findings.append(
                AnomalyFinding(
                    anomaly_id=f"ANOM-{uuid4().hex[:12]}",
                    anomaly_type="UNUSUAL_SOURCE_VOLUME",
                    severity=severity,
                    score=score,
                    timestamp=representative.timestamp,
                    source_ip=source_ip,
                    reason=(
                        f"Source IP {source_ip} generated {count} events "
                        f"during hour {hour_key}, which deviates from its "
                        f"historical baseline."
                    ),
                    evidence=[
                        f"Event count: {count}",
                        f"Baseline mean: {profile['mean']:.2f}",
                        f"Baseline stddev: {profile['stddev']:.2f}",
                        f"Z-score: {z_score:.2f}",
                    ],
                )
            )

    return findings
