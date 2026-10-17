"""
Benchmark the detection engine at different dataset sizes.
Uses in-memory SimpleNamespace events so no DB I/O is needed.
Ensures rules fire by generating events that trigger all major rules.
"""
import sys
import time
from types import SimpleNamespace
from typing import List

sys.path.insert(0, ".")

from src.detection.engine.rule_engine import DetectionEngine
from src.detection.rules.rule_registry import get_rule_library

DATASET_SIZES = [1_000, 10_000, 50_000, 100_000]


def _make_auth_events(n: int) -> List[SimpleNamespace]:
    """Generate n events that will trigger brute-force & spraying rules."""
    events = []
    # Each IP makes 20 failed attempts → triggers AUTH-001
    ips_needed = max(n // 20, 1)
    for ip_idx in range(ips_needed):
        ip = f"10.1.{ip_idx // 256 % 256}.{ip_idx % 256}"
        for attempt in range(20):
            idx = ip_idx * 20 + attempt
            if idx >= n:
                break
            events.append(SimpleNamespace(
                id=idx,
                event_id=f"DET-{idx:08d}",
                timestamp="2026-09-25 10:00:00",
                event_type="LOGIN_FAILED",
                event_category="authentication",
                source_ip=ip,
                username=f"user_{attempt % 5}",
                service="ssh",
                status="failed",
                http_method=None,
                http_path=None,
                response_code=None,
                source_type="authentication",
                user_agent=None,
                hostname=None,
                action=None,
                source_port=None,
                destination_ip=None,
                destination_port=None,
                raw_log="",
                ingested_at=None,
            ))
            if len(events) >= n:
                break
        if len(events) >= n:
            break

    # Fill remainder with normal login events
    while len(events) < n:
        i = len(events)
        events.append(SimpleNamespace(
            id=i,
            event_id=f"DET-{i:08d}",
            timestamp="2026-09-25 09:00:00",
            event_type="LOGIN_SUCCESS",
            event_category="authentication",
            source_ip=f"192.168.1.{i % 254 + 1}",
            username=f"normal_user_{i % 200}",
            service="ssh",
            status="success",
            http_method=None,
            http_path=None,
            response_code=None,
            source_type="authentication",
            user_agent=None,
            hostname=None,
            action=None,
            source_port=None,
            destination_ip=None,
            destination_port=None,
            raw_log="",
            ingested_at=None,
        ))

    return events[:n]


def run_detection_benchmark(sizes: List[int] = None) -> List[dict]:
    """Run detection engine benchmarks for given dataset sizes."""
    if sizes is None:
        sizes = DATASET_SIZES

    results = []
    for n in sizes:
        events = _make_auth_events(n)
        engine = DetectionEngine(get_rule_library())

        t0 = time.perf_counter()
        alerts = engine.run(events)
        elapsed = time.perf_counter() - t0

        result = {
            "benchmark": "detection",
            "dataset_size": n,
            "detection_time_s": round(elapsed, 4),
            "events_per_second": int(n / elapsed) if elapsed > 0 else 0,
            "alerts_generated": len(alerts),
        }
        results.append(result)
        print(
            f"  Detection {n:>8,} events | "
            f"{elapsed:.4f}s | "
            f"{result['events_per_second']:>10,} ev/s | "
            f"{len(alerts)} alerts"
        )

    return results


if __name__ == "__main__":
    print("=== Detection Benchmark ===")
    run_detection_benchmark()
