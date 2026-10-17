"""
Benchmark the log parsing pipeline at different dataset sizes.
Simulates field-extraction work done by log parsers using in-memory events.
"""
import sys
import time
import tracemalloc
from types import SimpleNamespace
from typing import List

sys.path.insert(0, ".")

DATASET_SIZES = [1_000, 10_000, 50_000, 100_000]


def _make_event(i: int) -> SimpleNamespace:
    """Create a synthetic event matching EventModel field layout."""
    category = ["authentication", "web", "firewall", "application", "system"][i % 5]
    event_types = {
        "authentication": "LOGIN_FAILED",
        "web": "HTTP_REQUEST",
        "firewall": "FIREWALL_EVENT",
        "application": "APP_ERROR",
        "system": "SYSTEM_EVENT",
    }
    return SimpleNamespace(
        id=i,
        event_id=f"BENCH-{i:08d}",
        timestamp="2026-09-25 10:00:00",
        event_type=event_types[category],
        event_category=category,
        source_ip=f"10.0.{(i // 256) % 256}.{i % 256}",
        username=f"user_{i % 500}" if category == "authentication" else None,
        service="ssh" if category == "authentication" else "http",
        status="failed" if category in ("authentication", "application") else "success",
        http_method="GET" if category == "web" else None,
        http_path=f"/api/resource/{i % 100}" if category == "web" else None,
        response_code=200 if category == "web" else None,
        source_type=category,
        user_agent=None,
        hostname=None,
        action=None,
        source_port=None,
        destination_ip=None,
        destination_port=None,
        raw_log=f"synthetic log entry {i}",
        ingested_at=None,
    )


def _simulate_parse(event: SimpleNamespace) -> dict:
    """Simulate field-extraction work a real parser would do."""
    return {
        "event_id": event.event_id,
        "event_type": event.event_type.upper().strip(),
        "category": event.event_category.lower().strip(),
        "source_ip": (event.source_ip or "").strip(),
        "username": (event.username or "").strip(),
        "service": (event.service or "").strip(),
        "status": (event.status or "").strip().lower(),
        "http_method": (event.http_method or "").upper(),
        "http_path": (event.http_path or "").strip(),
        "response_code": event.response_code,
    }


def run_parser_benchmark(sizes: List[int] = None) -> List[dict]:
    """Run parser benchmarks for given dataset sizes."""
    if sizes is None:
        sizes = DATASET_SIZES

    results = []
    for n in sizes:
        # Generate events
        events = [_make_event(i) for i in range(n)]

        # Measure parse time + memory
        tracemalloc.start()
        t0 = time.perf_counter()
        parsed = [_simulate_parse(e) for e in events]
        elapsed = time.perf_counter() - t0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        result = {
            "benchmark": "parser",
            "dataset_size": n,
            "parsing_time_s": round(elapsed, 4),
            "events_per_second": int(n / elapsed) if elapsed > 0 else 0,
            "memory_mb": round(peak_mem / (1024 * 1024), 2),
            "records_parsed": len(parsed),
        }
        results.append(result)
        print(
            f"  Parser  {n:>8,} events | "
            f"{elapsed:.4f}s | "
            f"{result['events_per_second']:>10,} ev/s | "
            f"{result['memory_mb']:.1f} MB"
        )

    return results


if __name__ == "__main__":
    print("=== Parser Benchmark ===")
    run_parser_benchmark()
