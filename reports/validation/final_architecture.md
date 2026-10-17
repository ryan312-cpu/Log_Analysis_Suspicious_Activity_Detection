# Final System Architecture Blueprint

**Project:** Log Analysis & Suspicious Activity Detection Platform  
**Completion Status:** All Phases (0 through 21) Fully Implemented and Validated  
**Platform Version:** 1.0.0 Production Ready  

---

## 1. End-to-End System Topology

The platform provides unified log ingestion, automated parsing, multi-tier threat detection, MITRE ATT&CK correlation, investigative graph visualization, container orchestration, and continuous runtime observability.

```
                    Raw Multi-Source Telemetry Ingestion
     [Linux Syslog]      [Apache / Nginx Access]      [Palo Alto / Fortinet FW]
            │                       │                            │
            ▼                       ▼                            ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │               Data Normalization & Parser Subsystem                   │
   │      (Regex-based schema unification to EventModel / SimpleNamespace)  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                   Storage & Persistence Engine                         │
   │               SQLite Analytical Database (SQLAlchemy ORM)              │
   │        Tables: events, alerts, incidents, rules, threat_intel          │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                    Core Threat Detection Engine                        │
   │   - 15 Rule Library (Authentication, Web, Firewall, App, System)       │
   │   - Isolation Forest Anomaly Detection Engine                          │
   │   - Sliding-Window Temporal Correlator (Multi-stage kill-chains)       │
   │   - MITRE ATT&CK Alert Enrichment Engine                               │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                    Investigation & Graph Engine                        │
   │      - IP / User Entity Profiling & Blast Radius Graph Generation      │
   │      - Threat Intelligence IOC Matching (AbuseIPDB, VirusTotal feeds)  │
   │      - Forensic PDF Report Synthesis (ReportLab Engine)                │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                       Hardened API Gateway                             │
   │     - FastAPI REST Service with Tiered RBAC (Analyst vs Admin)         │
   │     - Sliding-Window Rate Limiter (100 req/60s per client)             │
   │     - Ingress Sanitization (Blocks SQLi, XSS, Path Traversal, %00)     │
   │     - Observability & Metrics Middleware (GET /metrics, /health)       │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                     Nginx Perimeter & Frontend                         │
   │        - Multi-Stage Dockerized React SPA User Interface               │
   │        - Incident Management & Forensic Interactive Timeline           │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Directory Architecture

```
Log_Analysis_Suspicious_Activity_Detection/
├── .github/workflows/ci.yml           # Automated CI/CD (lint, test, git secrets, docker)
├── docker/
│   ├── backend.Dockerfile             # Python 3.12-slim ASGI backend container
│   ├── frontend.Dockerfile            # Multi-stage Node 20 / Nginx Alpine container
│   └── nginx.conf                     # Ingress proxy, SPA routing & security headers
├── docker-compose.yml                 # Multi-container service topology & volumes
├── docs/
│   ├── deployment.md                  # Deployment & operations runbook
│   └── monitoring.md                  # Observability, metrics, and health diagnostics
├── reports/
│   ├── deployment/deployment_report.md
│   ├── mitre/
│   │   ├── attack_coverage.md         # Matrix table & tactic density graphs
│   │   └── mitre_mapping_report.md    # Phase 20 Threat Intelligence report
│   ├── monitoring/monitoring_report.md# Phase 19 Observability report
│   ├── performance/
│   │   ├── benchmark_results.csv
│   │   ├── benchmark_results.json
│   │   ├── performance_report.html
│   │   └── scalability_chart.png
│   ├── security/
│   │   ├── npm_audit.json
│   │   ├── pip_audit.json
│   │   └── security_hardening_report.md
│   └── validation/
│       ├── controlled_validation.csv  # 8/8 Controlled threat scenarios
│       ├── controlled_validation.json
│       ├── final_architecture.md      # This document
│       └── phase21_summary.md         # Capstone validation certification
├── src/
│   ├── anomaly/                       # Unsupervised ML anomaly detection
│   ├── api/
│   │   ├── main.py                    # Gateway app with metrics & error handling
│   │   ├── routes/                    # Events, alerts, incidents, reports, intel
│   │   └── security/                  # RBAC, Rate limiting, Headers, Input validation
│   ├── detection/
│   │   ├── correlation/               # Temporal and cross-source correlator
│   │   ├── engine/                    # RuleEngine execution core
│   │   ├── mitre/                     # ATT&CK mapping, coverage, and enrichment
│   │   └── rules/                     # 15 Rule implementations across 5 domains
│   ├── monitoring/                    # Dual-sink logging, health probes, MetricsStore
│   ├── parsers/                       # Syslog, Apache, Auth, Firewall normalization
│   ├── performance/                   # Ingestion, parsing, detection, DB benchmarks
│   ├── storage/                       # Database engine, models, and migrations
│   ├── threat_intel/                  # IOC enrichment & reputation lookup
│   └── validation/                    # Scenario generator & validation test runner
└── tests/
    ├── detection/                     # Rule and engine tests
    ├── deployment/                    # Container & CI validation tests
    ├── mitre/                         # ATT&CK mapping & enrichment tests
    ├── monitoring/                    # Health, metrics, and logging tests
    ├── performance/                   # Throughput & scalability tests
    ├── security/                      # RBAC, input sanitization, rate limit tests
    └── validation/                    # Controlled scenario tests (CV-001 - CV-008)
```

---

## 3. Subsystem Metrics & Operational Benchmarks

- **Parsing Throughput:** ~330,000+ events per second.
- **Rule Detection Throughput:** ~280,000+ events per second across all 15 rules.
- **Database Bulk Ingestion:** ~70,000 events per second.
- **Security Hardening:** 35 automated security tests verifying OWASP Top 10 mitigation.
- **MITRE Coverage:** 15 rules mapped across 7 enterprise tactics with automated alert decoration.
- **Adversary Validation:** 8/8 attack scenarios successfully identified with exact severity ratings.
- **Test Suite Total:** 127 automated regression tests passing in < 8 seconds.
