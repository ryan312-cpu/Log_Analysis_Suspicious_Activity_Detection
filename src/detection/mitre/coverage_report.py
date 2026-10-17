from pathlib import Path
from typing import Optional

from src.detection.mitre.attack_mapping import ATTACK_MAPPING, get_tactic_coverage

REPORT_DIR = Path("reports/mitre")


def generate_coverage_report() -> str:
    """Generate a structured Markdown MITRE ATT&CK coverage report."""
    coverage = get_tactic_coverage()
    total_rules = len(ATTACK_MAPPING)

    lines = [
        "# MITRE ATT&CK Framework Coverage Report",
        "",
        "**Platform:** Log Analysis & Suspicious Activity Detection Engine  ",
        f"**Total Detection Rules Mapped:** {total_rules}  ",
        f"**Tactics Covered:** {len(coverage)}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "This report maps all active detection rules in the platform to the MITRE ATT&CK Enterprise Matrix.",
        "Mapping each rule to standardized tactics, techniques, and sub-techniques ensures alignment with industry",
        "threat intelligence standards, enables standardized adversary emulation testing, and identifies detection gaps.",
        "",
        "---",
        "",
        "## 2. Tactic Coverage Distribution",
        "",
        "| MITRE Tactic | Covered Rules | Density Graph |",
        "| :--- | :---: | :--- |",
    ]

    for tactic, count in coverage.items():
        bar = "█" * (count * 3)
        lines.append(f"| **{tactic}** | {count} | `{bar}` |")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Comprehensive Rule-to-Technique Mapping",
        "",
        "| Rule ID | Rule Name | Tactic (ID) | Technique (ID) | Sub-Technique (ID) | MITRE Reference |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for rule_id, info in sorted(ATTACK_MAPPING.items()):
        sub = info.get("subtechnique") or "—"
        sub_id = info.get("subtechnique_id") or "—"
        url = info.get("url", "")
        link = f"[{info['technique_id']}]({url})" if url else info.get("technique_id", "—")
        lines.append(
            f"| `{rule_id}` | {info['rule_name']} | {info['tactic']} (`{info['tactic_id']}`) | "
            f"{info['technique']} (`{info['technique_id']}`) | {sub} (`{sub_id}`) | {link} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Coverage Analysis & Threat Spectrum",
        "",
        "- **Primary Focus (Credential Access & Discovery):** 5 rules address Credential Access (`T1110` Brute Force / Password Spraying) and 3 rules address Discovery (`T1046` Network Service Discovery). This represents the primary initial and lateral compromise vectors in enterprise logs.",
        "- **Impact & Defense Evasion:** Defense Evasion (`T1078`, `T1562`) and Impact (`T1489`, `T1498`) are actively covered to monitor post-exploitation disruption and anti-forensic activities.",
        "- **Reconnaissance & Initial Access:** Ingress probes (`FW-001`, `WEB-004`) capture external reconnaissance and web application exploitation attempts.",
        "",
        "---",
        "*Report generated automatically by the Security Analytics MITRE Subsystem.*",
    ])

    return "\n".join(lines)


def save_coverage_report(output_path: Optional[Path] = None) -> Path:
    """Save the generated ATT&CK coverage report to disk."""
    if output_path is None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        target = REPORT_DIR / "attack_coverage.md"
    else:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

    content = generate_coverage_report()
    target.write_text(content, encoding="utf-8")
    return target


if __name__ == "__main__":
    path = save_coverage_report()
    print(f"Coverage report saved to: {path}")
