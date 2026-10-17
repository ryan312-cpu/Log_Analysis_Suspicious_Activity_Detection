import threading
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MetricsStore:
    events_processed_total: int = 0
    alerts_generated_total: int = 0
    incidents_created_total: int = 0
    parser_errors_total: int = 0
    detection_errors_total: int = 0
    api_requests_total: int = 0
    _api_request_durations: List[float] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock)


    def increment(self, metric: str, value: int = 1):
        """Thread-safe counter increment."""
        with self._lock:
            current = getattr(self, metric, 0)
            setattr(self, metric, current + value)

    def record_api_request(self, duration_s: float):
        """Record an API request duration."""
        with self._lock:
            self.api_requests_total += 1
            self._api_request_durations.append(duration_s)
            if len(self._api_request_durations) > 1000:
                self._api_request_durations = self._api_request_durations[-1000:]

    def get_api_avg_duration(self) -> float:
        """Calculate the average latency of recent API requests."""
        with self._lock:
            if not self._api_request_durations:
                return 0.0
            return sum(self._api_request_durations) / len(self._api_request_durations)

    def snapshot(self) -> Dict[str, object]:
        """Return a point-in-time dictionary snapshot of all telemetry metrics."""
        with self._lock:
            return {
                "events_processed_total": self.events_processed_total,
                "alerts_generated_total": self.alerts_generated_total,
                "incidents_created_total": self.incidents_created_total,
                "parser_errors_total": self.parser_errors_total,
                "detection_errors_total": self.detection_errors_total,
                "api_requests_total": self.api_requests_total,
                "api_request_avg_duration_s": round(self.get_api_avg_duration(), 6),
            }


# Process-wide singleton
_metrics_instance = MetricsStore()


def get_metrics() -> MetricsStore:
    """Return the global MetricsStore singleton."""
    return _metrics_instance


def reset_metrics():
    """Reset the metrics counters to zero (useful in tests)."""
    global _metrics_instance
    _metrics_instance = MetricsStore()
