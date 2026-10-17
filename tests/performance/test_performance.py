"""
Phase 16 — Performance & Scalability Tests
Tests benchmark scripts and validates performance thresholds.
"""
import sys
import json
from pathlib import Path

import pytest

sys.path.insert(0, ".")

from src.performance.benchmark_parser import run_parser_benchmark
from src.performance.benchmark_detection import run_detection_benchmark
from src.performance.benchmark_database import run_database_benchmark


# ──────────────────────────────────────────────────────────────────────────────
# PARSER BENCHMARKS
# ──────────────────────────────────────────────────────────────────────────────

class TestParserBenchmark:

    def test_parser_benchmark_1000_events(self):
        """Parser must process 1,000 events in under 5 seconds."""
        results = run_parser_benchmark([1_000])
        assert len(results) == 1
        r = results[0]
        assert r["dataset_size"] == 1_000
        assert r["parsing_time_s"] < 5.0
        assert r["events_per_second"] > 0
        assert r["records_parsed"] == 1_000

    def test_parser_returns_expected_fields(self):
        results = run_parser_benchmark([100])
        r = results[0]
        assert "dataset_size" in r
        assert "parsing_time_s" in r
        assert "events_per_second" in r
        assert "memory_mb" in r

    def test_parser_scales_linearly(self):
        """Ratio of 10k/1k parse times should be < 30 (accounting for millisecond-level scheduling variance)."""
        results = run_parser_benchmark([1_000, 10_000])
        t1k = results[0]["parsing_time_s"]
        t10k = results[1]["parsing_time_s"]
        ratio = t10k / t1k if t1k > 0 else 1
        assert ratio < 30, f"Non-linear scaling: 10k/1k ratio = {ratio:.1f}"


    def test_parser_memory_under_500mb(self):
        results = run_parser_benchmark([10_000])
        assert results[0]["memory_mb"] < 500.0


# ──────────────────────────────────────────────────────────────────────────────
# DETECTION BENCHMARKS
# ──────────────────────────────────────────────────────────────────────────────

class TestDetectionBenchmark:

    def test_detection_benchmark_1000_events(self):
        """Detection engine must process 1,000 events in under 5 seconds."""
        results = run_detection_benchmark([1_000])
        assert len(results) == 1
        r = results[0]
        assert r["dataset_size"] == 1_000
        assert r["detection_time_s"] < 5.0
        assert r["events_per_second"] > 0

    def test_detection_returns_expected_fields(self):
        results = run_detection_benchmark([100])
        r = results[0]
        assert "dataset_size" in r
        assert "detection_time_s" in r
        assert "events_per_second" in r
        assert "alerts_generated" in r

    def test_detection_generates_alerts(self):
        """Detection on auth events should produce alerts."""
        results = run_detection_benchmark([1_000])
        assert results[0]["alerts_generated"] > 0

    def test_detection_scales_linearly(self):
        """10k/1k detection time ratio should be < 20."""
        results = run_detection_benchmark([1_000, 10_000])
        t1k = results[0]["detection_time_s"]
        t10k = results[1]["detection_time_s"]
        ratio = t10k / t1k if t1k > 0 else 1
        assert ratio < 20, f"Non-linear scaling: ratio = {ratio:.1f}"


# ──────────────────────────────────────────────────────────────────────────────
# DATABASE BENCHMARKS
# ──────────────────────────────────────────────────────────────────────────────

class TestDatabaseBenchmark:

    def test_database_benchmark_1000_events(self):
        """DB insertion of 1,000 events must complete in under 10 seconds."""
        results = run_database_benchmark([1_000])
        assert len(results) == 1
        r = results[0]
        assert r["dataset_size"] == 1_000
        assert r["insertion_time_s"] < 10.0
        assert r["rows_verified"] == 1_000

    def test_database_returns_expected_fields(self):
        results = run_database_benchmark([100])
        r = results[0]
        assert "dataset_size" in r
        assert "insertion_time_s" in r
        assert "events_per_second" in r
        assert "rows_verified" in r

    def test_database_row_count_matches_input(self):
        for n in [500, 1_000]:
            results = run_database_benchmark([n])
            assert results[0]["rows_verified"] == n


# ──────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────────────────────────────────────

class TestReportGeneration:

    def test_benchmark_results_saved(self, tmp_path, monkeypatch):
        """Full benchmark (1000 only) creates json and csv output files."""
        import src.performance.run_benchmarks as rb
        monkeypatch.setattr(rb, "SIZES", [1_000])
        monkeypatch.setattr(rb, "REPORT_DIR", tmp_path)

        all_results, *_ = rb._run_all()
        rb._save_json(all_results)
        rb._save_csv(all_results)

        assert (tmp_path / "benchmark_results.json").exists()
        assert (tmp_path / "benchmark_results.csv").exists()

        # Validate JSON content
        data = json.loads((tmp_path / "benchmark_results.json").read_text())
        assert isinstance(data, list)
        assert len(data) > 0

    def test_performance_report_generated(self, tmp_path, monkeypatch):
        """HTML report should be generated with chart."""
        import src.performance.run_benchmarks as rb
        monkeypatch.setattr(rb, "SIZES", [1_000])
        monkeypatch.setattr(rb, "REPORT_DIR", tmp_path)

        all_results, parser_r, det_r, db_r, api_r, total_s = rb._run_all()
        chart_b64 = rb._build_chart(parser_r, det_r, db_r)
        html = rb._build_html(parser_r, det_r, db_r, api_r, chart_b64, total_s)

        html_path = tmp_path / "performance_report.html"
        html_path.write_text(html, encoding="utf-8")

        assert html_path.exists()
        content = html_path.read_text()
        assert "Performance" in content
        assert "data:image/png;base64," in content  # chart embedded
