from typing import Any, Dict

from src.detection.mitre.attack_mapping import get_attack_info


def enrich_alert_with_mitre(alert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert dictionary with corresponding MITRE ATT&CK metadata.
    If the rule ID is not mapped or unrecognized, returns alert_dict unmodified.
    """
    rule_id = alert_dict.get("rule_id", "")
    info = get_attack_info(rule_id)
    if info:
        alert_dict["mitre_tactic"] = info.get("tactic")
        alert_dict["mitre_tactic_id"] = info.get("tactic_id")
        alert_dict["mitre_technique"] = info.get("technique")
        alert_dict["mitre_technique_id"] = info.get("technique_id")
        alert_dict["mitre_subtechnique"] = info.get("subtechnique")
        alert_dict["mitre_subtechnique_id"] = info.get("subtechnique_id")
        alert_dict["mitre_url"] = info.get("url")
    return alert_dict
