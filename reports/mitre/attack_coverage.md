# MITRE ATT&CK Framework Coverage Report

**Platform:** Log Analysis & Suspicious Activity Detection Engine  
**Total Detection Rules Mapped:** 15  
**Tactics Covered:** 8  

---

## 1. Executive Summary

This report maps all active detection rules in the platform to the MITRE ATT&CK Enterprise Matrix.
Mapping each rule to standardized tactics, techniques, and sub-techniques ensures alignment with industry
threat intelligence standards, enables standardized adversary emulation testing, and identifies detection gaps.

---

## 2. Tactic Coverage Distribution

| MITRE Tactic | Covered Rules | Density Graph |
| :--- | :---: | :--- |
| **Credential Access** | 4 | `████████████` |
| **Discovery** | 3 | `█████████` |
| **Defense Evasion** | 2 | `██████` |
| **Impact** | 2 | `██████` |
| **Persistence** | 1 | `███` |
| **Lateral Movement** | 1 | `███` |
| **Initial Access** | 1 | `███` |
| **Reconnaissance** | 1 | `███` |

---

## 3. Comprehensive Rule-to-Technique Mapping

| Rule ID | Rule Name | Tactic (ID) | Technique (ID) | Sub-Technique (ID) | MITRE Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `APP-001` | Application Service Failure Burst | Impact (`TA0040`) | Service Stop (`T1489`) | — (`—`) | [T1489](https://attack.mitre.org/techniques/T1489/) |
| `AUTH-001` | Multiple Failed Login Attempts | Credential Access (`TA0006`) | Brute Force (`T1110`) | Password Guessing (`T1110.001`) | [T1110](https://attack.mitre.org/techniques/T1110/001/) |
| `AUTH-002` | Access Denied Authorization Failure | Defense Evasion (`TA0005`) | Valid Accounts (`T1078`) | — (`—`) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `AUTH-003` | Unusual Login Time | Persistence (`TA0003`) | Valid Accounts (`T1078`) | — (`—`) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `AUTH-004` | Successful Login After Multiple Failures | Credential Access (`TA0006`) | Brute Force (`T1110`) | — (`—`) | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `AUTH-005` | Password Spraying Detection | Credential Access (`TA0006`) | Brute Force (`T1110`) | Password Spraying (`T1110.003`) | [T1110](https://attack.mitre.org/techniques/T1110/003/) |
| `AUTH-006` | Account Lockout Spike | Credential Access (`TA0006`) | Brute Force (`T1110`) | — (`—`) | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `AUTH-007` | Concurrent Logins from Multiple Geographies | Lateral Movement (`TA0008`) | Use Alternate Authentication Material (`T1550`) | — (`—`) | [T1550](https://attack.mitre.org/techniques/T1550/) |
| `FW-001` | Firewall Port Scan Denial Burst | Reconnaissance (`TA0043`) | Active Scanning (`T1595`) | Scanning IP Blocks (`T1595.001`) | [T1595](https://attack.mitre.org/techniques/T1595/001/) |
| `SYS-001` | Security Service Failure / Impair Defenses | Defense Evasion (`TA0005`) | Impair Defenses (`T1562`) | Disable or Modify Tools (`T1562.001`) | [T1562](https://attack.mitre.org/techniques/T1562/001/) |
| `WEB-001` | Web Reconnaissance Scanning | Discovery (`TA0007`) | Network Service Discovery (`T1046`) | — (`—`) | [T1046](https://attack.mitre.org/techniques/T1046/) |
| `WEB-002` | Excessive Web Request Volume | Impact (`TA0040`) | Network Denial of Service (`T1498`) | — (`—`) | [T1498](https://attack.mitre.org/techniques/T1498/) |
| `WEB-003` | Sensitive File Directory Traversal | Discovery (`TA0007`) | Network Service Discovery (`T1046`) | — (`—`) | [T1046](https://attack.mitre.org/techniques/T1046/) |
| `WEB-004` | Web Application Exploitation Pattern | Initial Access (`TA0001`) | Exploit Public-Facing Application (`T1190`) | — (`—`) | [T1190](https://attack.mitre.org/techniques/T1190/) |
| `WEB-005` | Restricted Admin Path Enumeration | Discovery (`TA0007`) | Network Service Discovery (`T1046`) | — (`—`) | [T1046](https://attack.mitre.org/techniques/T1046/) |

---

## 4. Coverage Analysis & Threat Spectrum

- **Primary Focus (Credential Access & Discovery):** 5 rules address Credential Access (`T1110` Brute Force / Password Spraying) and 3 rules address Discovery (`T1046` Network Service Discovery). This represents the primary initial and lateral compromise vectors in enterprise logs.
- **Impact & Defense Evasion:** Defense Evasion (`T1078`, `T1562`) and Impact (`T1489`, `T1498`) are actively covered to monitor post-exploitation disruption and anti-forensic activities.
- **Reconnaissance & Initial Access:** Ingress probes (`FW-001`, `WEB-004`) capture external reconnaissance and web application exploitation attempts.

---
*Report generated automatically by the Security Analytics MITRE Subsystem.*