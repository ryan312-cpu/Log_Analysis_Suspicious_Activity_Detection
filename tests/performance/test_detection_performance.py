"""
Phase 15 – Performance Tests
Verifies the detection engine meets latency and throughput requirements.
"""
import time
from types import SimpleNamespace
from pathlib import Path

import pandas as pd
import pytest

from src.detection.engine.rule_engine import DetectionEngine
from src.detection.rules.rule_registry import get_rule_library


LABELLED_CSV = Path("data/labelled/labelled_events.csv")


def _load_events():
    df = pd.read_csv(LABELLED_CSV)
    events = []
    for idx, row in df.iterrows():
        raw_rc = row.get("response_code", "")
        try:
            rc = int(float(raw_rc)) if pd.notna(raw_rc) and str(raw_rc).strip() else None
        except (ValueError, TypeError):
            rc = None
        raw_http = row.get("http_method", "")
        raw_path = row.get("http_path", "")
        events.append(SimpleNamespace(
            id               = idx,
            event_id         = f"PERF-{idx:06d}",
            timestamp        = str(row.get("timestamp", "")),
            event_type       = str(row.get("event_type", "")).strip().upper(),
            event_category   = str(row.get("event_category", "")).strip().lower(),
            source_ip        = str(row.get("source_ip", "")).strip() or None,
            source_port      = None,
            destination_ip   = None,
            destination_port = None,
            username         = str(row.get("username", "")).strip() or None,
            hostname         = None,
            service          = str(row.get("service", "")).strip() or None,
            action           = None,
            status           = str(row.get("status", "")).strip().lower() or None,
            http_method      = str(raw_http).strip().upper() if pd.notna(raw_http) and str(raw_http).strip() else None,
            http_path        = str(raw_path).strip() if pd.notna(raw_path) and str(raw_path).strip() else None,
            response_code    = rc,
            user_agent       = None,
            source_type      = str(row.get("event_category", "")).strip().lower(),
            raw_log          = "",
            ingested_at      = None,
        ))
    return events


@pytest.fixture(scope="module")
def events():
    return _load_events()


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine(get_rule_library())


class TestDetectionPerformance:

    def test_detection_completes_within_1_second(self, events, engine):
        """Detection over 132 events must complete in under 1 second."""
        start = time.perf_counter()
        alerts = engine.run(events)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"Detection took {elapsed:.3f}s, expected < 1.0s"
        )

    def test_detection_throughput_above_1000_events_per_second(self, events, engine):
        """Throughput must exceed 1 000 events/second."""
        start = time.perf_counter()
        engine.run(events)
        elapsed = time.perf_counter() - start
        throughput = len(events) / elapsed if elapsed > 0 else float("inf")
        assert throughput >= 1000, (
            f"Throughput {throughput:.0f} events/s is below 1000 events/s threshold"
        )

    def test_rules_count(self, engine):
        """All 15 detection rules must be registered."""
        assert len(engine.rules) == 15

    def test_all_rules_fire_on_labelled_dataset(self, events, engine):
        """Every rule should generate at least one alert on the labelled dataset."""
        alerts = engine.run(events)
        fired_rules = {a.rule_id for a in alerts}
        all_rules   = {r.rule_id for r in engine.rules}
        missing = all_rules - fired_rules
        assert not missing, (
            f"The following rules did not fire: {missing}"
        )

    def test_no_alerts_on_normal_only_events(self, events, engine):
        """
        On a dataset containing only normal events, suspicious-status rules
        (brute-force, spraying, etc.) should generate zero alerts.
        NOTE: AUTH-003 (unusual login time) may still fire if timestamps fall
        outside business hours, so we only check the count stays reasonable.
        """
        # Filter to normal events only (label == 'normal' in CSV)
        df = pd.read_csv(LABELLED_CSV)
        normal_df = df[df["label"] == "normal"]

        normal_events = []
        for idx, row in normal_df.iterrows():
            raw_rc = row.get("response_code", "")
            try:
                rc = int(float(raw_rc)) if pd.notna(raw_rc) and str(raw_rc).strip() else None
            except (ValueError, TypeError):
                rc = None
            raw_http = row.get("http_method", "")
            raw_path = row.get("http_path", "")
            normal_events.append(SimpleNamespace(
                id               = idx,
                event_id         = f"NRM-{idx:06d}",
                timestamp        = str(row.get("timestamp", "")),
                event_type       = str(row.get("event_type", "")).strip().upper(),
                event_category   = str(row.get("event_category", "")).strip().lower(),
                source_ip        = str(row.get("source_ip", "")).strip() or None,
                source_port      = None,
                destination_ip   = None,
                destination_port = None,
                username         = str(row.get("username", "")).strip() or None,
                hostname         = None,
                service          = str(row.get("service", "")).strip() or None,
                action           = None,
                status           = str(row.get("status", "")).strip().lower() or None,
                http_method      = str(raw_http).strip().upper() if pd.notna(raw_http) and str(raw_http).strip() else None,
                http_path        = str(raw_path).strip() if pd.notna(raw_path) and str(raw_path).strip() else None,
                response_code    = rc,
                user_agent       = None,
                source_type      = str(row.get("event_category", "")).strip().lower(),
                raw_log          = "",
                ingested_at      = None,
            ))

        alerts = engine.run(normal_events)
        # No brute-force style alerts should fire on clean normal traffic
        rule_ids = {a.rule_id for a in alerts}
        brute_force_rules = {
            "AUTH-001", "AUTH-004", "AUTH-005", "AUTH-006",
            "WEB-001", "WEB-004", "FW-001",
        }
        fired_brute = rule_ids & brute_force_rules
        assert not fired_brute, (
            f"Brute-force rules fired on normal-only events: {fired_brute}"
        )
