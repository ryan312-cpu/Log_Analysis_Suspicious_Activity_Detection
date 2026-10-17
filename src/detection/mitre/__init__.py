"""
MITRE ATT&CK framework mapping, alert enrichment, and coverage reporting.
"""
from src.detection.mitre.attack_mapping import (
    ATTACK_MAPPING,
    get_attack_info,
    get_tactic_coverage,
)
from src.detection.mitre.enrichment import enrich_alert_with_mitre
from src.detection.mitre.coverage_report import generate_coverage_report, save_coverage_report

__all__ = [
    "ATTACK_MAPPING",
    "get_attack_info",
    "get_tactic_coverage",
    "enrich_alert_with_mitre",
    "generate_coverage_report",
    "save_coverage_report",
]
