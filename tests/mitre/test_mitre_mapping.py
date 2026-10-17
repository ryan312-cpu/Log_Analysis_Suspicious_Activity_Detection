import dataclasses
from pathlib import Path

from src.detection.models.rule_metadata import RuleMetadata
from src.detection.mitre.attack_mapping import (
    ATTACK_MAPPING,
    get_attack_info,
    get_tactic_coverage,
)
from src.detection.mitre.enrichment import enrich_alert_with_mitre
from src.detection.mitre.coverage_report import (
    generate_coverage_report,
    save_coverage_report,
)


def test_all_15_rules_mapped():
    assert len(ATTACK_MAPPING) == 15
    expected_rules = [
        "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006", "AUTH-007",
        "WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005",
        "FW-001", "APP-001", "SYS-001",
    ]
    for r in expected_rules:
        assert r in ATTACK_MAPPING


def test_auth001_maps_to_credential_access():
    info = get_attack_info("AUTH-001")
    assert info["tactic"] == "Credential Access"
    assert info["technique"] == "Brute Force"
    assert info["technique_id"] == "T1110"
    assert info["subtechnique"] == "Password Guessing"


def test_auth005_maps_to_password_spraying():
    info = get_attack_info("AUTH-005")
    assert info["tactic"] == "Credential Access"
    assert info["subtechnique"] == "Password Spraying"
    assert info["subtechnique_id"] == "T1110.003"


def test_all_rules_have_technique_id():
    for rule_id, info in ATTACK_MAPPING.items():
        assert "technique_id" in info
        assert info["technique_id"].startswith("T"), f"Invalid technique_id in {rule_id}"


def test_all_rules_have_tactic_id():
    for rule_id, info in ATTACK_MAPPING.items():
        assert "tactic_id" in info
        assert info["tactic_id"].startswith("TA"), f"Invalid tactic_id in {rule_id}"


def test_all_rules_have_url():
    for rule_id, info in ATTACK_MAPPING.items():
        assert "url" in info
        assert info["url"].startswith("https://attack.mitre.org/"), f"Invalid URL in {rule_id}"


def test_tactic_coverage_returns_dict():
    coverage = get_tactic_coverage()
    assert isinstance(coverage, dict)
    assert len(coverage) >= 6
    assert sum(coverage.values()) == 15


def test_credential_access_has_highest_or_tied_coverage():
    coverage = get_tactic_coverage()
    assert "Credential Access" in coverage
    assert coverage["Credential Access"] >= 4


def test_enrich_alert_adds_mitre_fields():
    raw_alert = {
        "rule_id": "AUTH-001",
        "severity": "HIGH",
        "message": "Multiple failed logins",
    }
    enriched = enrich_alert_with_mitre(raw_alert)
    assert enriched["mitre_tactic"] == "Credential Access"
    assert enriched["mitre_technique_id"] == "T1110"
    assert enriched["mitre_subtechnique_id"] == "T1110.001"
    assert "https://attack.mitre.org" in enriched["mitre_url"]


def test_enrich_unknown_rule_safe():
    raw_alert = {
        "rule_id": "UNKNOWN-999",
        "severity": "LOW",
    }
    enriched = enrich_alert_with_mitre(raw_alert)
    assert "mitre_tactic" not in enriched
    assert enriched["rule_id"] == "UNKNOWN-999"


def test_generate_coverage_report_contains_all_rules():
    report = generate_coverage_report()
    assert "# MITRE ATT&CK Framework Coverage Report" in report
    for rule_id in ATTACK_MAPPING.keys():
        assert f"`{rule_id}`" in report


def test_save_coverage_report_creates_file(tmp_path):
    target = tmp_path / "custom_report.md"
    saved = save_coverage_report(target)
    assert saved.exists()
    content = saved.read_text(encoding="utf-8")
    assert "MITRE ATT&CK" in content


def test_rule_metadata_dataclass_fields():
    field_names = [f.name for f in dataclasses.fields(RuleMetadata)]
    expected = [
        "mitre_tactic",
        "mitre_technique",
        "mitre_technique_id",
        "mitre_subtechnique",
        "mitre_subtechnique_id",
        "mitre_url",
    ]
    for exp in expected:
        assert exp in field_names, f"RuleMetadata missing {exp}"
