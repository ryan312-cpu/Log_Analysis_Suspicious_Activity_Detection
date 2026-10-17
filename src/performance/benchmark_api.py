"""
Benchmark the FastAPI /api/v1/events endpoint response times.
Skips gracefully if the server is not running.
"""
import sys
import time
from typing import List

sys.path.insert(0, ".")

API_BASE = "http://127.0.0.1:8000"
REQUEST_COUNTS = [10, 50, 100]


def run_api_benchmark(request_counts: List[int] = None) -> List[dict]:
    """Benchmark API endpoint. Returns empty list if server not reachable."""
    if request_counts is None:
        request_counts = REQUEST_COUNTS

    try:
        import httpx
        # Quick connectivity check
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{API_BASE}/health")
            if resp.status_code != 200:
                print("  API server not healthy, skipping API benchmark.")
                return []
    except Exception:
        print("  API server not reachable, skipping API benchmark.")
        return []

    results = []
    for n in request_counts:
        durations = []
        errors = 0
        try:
            with httpx.Client(timeout=10.0) as client:
                for _ in range(n):
                    t0 = time.perf_counter()
                    try:
                        client.get(f"{API_BASE}/api/v1/events?limit=10")
                        durations.append(time.perf_counter() - t0)
                    except Exception:
                        errors += 1
        except Exception as e:
            print(f"  API benchmark error: {e}")
            continue

        if not durations:
            continue

        avg = sum(durations) / len(durations)
        result = {
            "benchmark": "api",
            "requests": n,
            "avg_response_time_s": round(avg, 4),
            "min_response_time_s": round(min(durations), 4),
            "max_response_time_s": round(max(durations), 4),
            "requests_per_second": round(1 / avg, 1) if avg > 0 else 0,
            "errors": errors,
        }
        results.append(result)
        print(
            f"  API {n:>4} requests | "
            f"avg={avg:.4f}s | "
            f"min={min(durations):.4f}s | "
            f"max={max(durations):.4f}s"
        )

    return results


if __name__ == "__main__":
    print("=== API Benchmark ===")
    run_api_benchmark()
