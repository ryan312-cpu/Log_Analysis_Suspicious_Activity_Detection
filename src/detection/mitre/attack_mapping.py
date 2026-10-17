"""
MITRE ATT&CK Enterprise Matrix mappings for detection rules.
Provides structured mappings from rule IDs to tactics, techniques, and URLs.
"""
from typing import Any, Dict

ATTACK_MAPPING: Dict[str, Dict[str, Any]] = {
    "AUTH-001": {
        "rule_name": "Multiple Failed Login Attempts",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "subtechnique": "Password Guessing",
        "subtechnique_id": "T1110.001",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "AUTH-002": {
        "rule_name": "Access Denied Authorization Failure",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "AUTH-003": {
        "rule_name": "Unusual Login Time",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "AUTH-004": {
        "rule_name": "Successful Login After Multiple Failures",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "AUTH-005": {
        "rule_name": "Password Spraying Detection",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "subtechnique": "Password Spraying",
        "subtechnique_id": "T1110.003",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "AUTH-006": {
        "rule_name": "Account Lockout Spike",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "AUTH-007": {
        "rule_name": "Concurrent Logins from Multiple Geographies",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Use Alternate Authentication Material",
        "technique_id": "T1550",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1550/",
    },
    "WEB-001": {
        "rule_name": "Web Reconnaissance Scanning",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "WEB-002": {
        "rule_name": "Excessive Web Request Volume",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "WEB-003": {
        "rule_name": "Sensitive File Directory Traversal",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "WEB-004": {
        "rule_name": "Web Application Exploitation Pattern",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "WEB-005": {
        "rule_name": "Restricted Admin Path Enumeration",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "FW-001": {
        "rule_name": "Firewall Port Scan Denial Burst",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique": "Active Scanning",
        "technique_id": "T1595",
        "subtechnique": "Scanning IP Blocks",
        "subtechnique_id": "T1595.001",
        "url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "APP-001": {
        "rule_name": "Application Service Failure Burst",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Service Stop",
        "technique_id": "T1489",
        "subtechnique": None,
        "subtechnique_id": None,
        "url": "https://attack.mitre.org/techniques/T1489/",
    },
    "SYS-001": {
        "rule_name": "Security Service Failure / Impair Defenses",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Impair Defenses",
        "technique_id": "T1562",
        "subtechnique": "Disable or Modify Tools",
        "subtechnique_id": "T1562.001",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
}


def get_attack_info(rule_id: str) -> Dict[str, Any]:
    """Retrieve ATT&CK mapping metadata for a specific rule ID."""
    return ATTACK_MAPPING.get(rule_id, {})


def get_tactic_coverage() -> Dict[str, int]:
    """Aggregate rule counts across all MITRE ATT&CK tactics."""
    coverage: Dict[str, int] = {}
    for info in ATTACK_MAPPING.values():
        tactic = info.get("tactic")
        if tactic:
            coverage[tactic] = coverage.get(tactic, 0) + 1
    return dict(sorted(coverage.items(), key=lambda x: -x[1]))
