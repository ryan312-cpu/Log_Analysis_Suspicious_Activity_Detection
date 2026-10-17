import json
from pathlib import Path

from src.detection.engine.rule_engine import DetectionEngine
from src.detection.rules.rule_registry import get_rule_library
from src.validation.controlled_runner import (
    run_controlled_validation,
    save_results,
)
from src.validation.scenario_generator import (
    scenario_application_errors,
    scenario_brute_force,
    scenario_excessive_requests,
    scenario_firewall_denial_burst,
    scenario_login_after_failures,
    scenario_password_spraying,
    scenario_service_failures,
    scenario_web_enumeration,
)

ROOT = Path(__file__).resolve().parents[2]


def test_scenario_brute_force_generates_events():
    events = scenario_brute_force(count=6)
    assert len(events) >= 5
    assert all(e.event_type == "LOGIN_FAILED" for e in events)


def test_scenario_password_spraying_has_different_users():
    events = scenario_password_spraying(count=5)
    users = {e.username for e in events}
    assert len(users) == 5
    assert len({e.source_ip for e in events}) == 1


def test_scenario_login_after_failures_ends_with_success():
    events = scenario_login_after_failures(failures=4)
    assert len(events) == 5
    assert events[-1].event_type == "LOGIN_SUCCESS"
    assert events[-1].status == "success"


def test_scenario_web_enumeration_uses_sensitive_paths():
    events = scenario_web_enumeration()
    paths = [e.http_path for e in events]
    assert any("/wp-admin" in p for p in paths)
    assert any("/.env" in p for p in paths)


def test_cv001_auth001_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_brute_force()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "AUTH-001" in rules
    auth_alert = [a for a in alerts if a.rule_id == "AUTH-001"][0]
    assert auth_alert.severity == "HIGH"


def test_cv002_auth005_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_password_spraying()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "AUTH-005" in rules


def test_cv003_auth004_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_login_after_failures()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "AUTH-004" in rules
    auth_alert = [a for a in alerts if a.rule_id == "AUTH-004"][0]
    assert auth_alert.severity == "CRITICAL"


def test_cv004_web005_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_web_enumeration()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "WEB-005" in rules


def test_cv005_web002_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_excessive_requests(count=8)
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "WEB-002" in rules


def test_cv006_fw001_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_firewall_denial_burst()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "FW-001" in rules


def test_cv007_app001_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_application_errors()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "APP-001" in rules


def test_cv008_sys001_fires():
    engine = DetectionEngine(get_rule_library())
    events = scenario_service_failures()
    alerts = engine.run(events)
    rules = {a.rule_id for a in alerts}
    assert "SYS-001" in rules


def test_all_8_scenarios_pass():
    results = run_controlled_validation()
    assert len(results) == 8
    assert all(r["Status"] == "PASS" for r in results)


def test_controlled_validation_saves_csv_and_json():
    results = run_controlled_validation()
    csv_file, json_file = save_results(results)
    assert csv_file.exists()
    assert json_file.exists()

    # Verify JSON content
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 8
    assert data[0]["Test ID"] == "CV-001"
