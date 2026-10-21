# Log Analysis & Suspicious Activity Detection Platform
## Capstone Project Report

**Author:** ryan312-cpu  
**Project Repository:** https://github.com/ryan312-cpu/Log_Analysis_Suspicious_Activity_Detection  
**Submission Date:** October 2026  
**Technology Stack:** Python 3.12 · FastAPI · SQLAlchemy · SQLite · React 18 · Vite · Docker  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Introduction & Problem Statement](#2-introduction--problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Implementation Details](#4-implementation-details)
   - 4.1 [Log Ingestion & Parsing](#41-log-ingestion--parsing)
   - 4.2 [Normalisation & Storage](#42-normalisation--storage)
   - 4.3 [Detection Engine & Rules](#43-detection-engine--rules)
   - 4.4 [Threat Intelligence](#44-threat-intelligence)
   - 4.5 [Incident Management](#45-incident-management)
   - 4.6 [REST API Backend](#46-rest-api-backend)
   - 4.7 [SOC Dashboard Frontend](#47-soc-dashboard-frontend)
   - 4.8 [Reporting](#48-reporting)
5. [Security Hardening](#5-security-hardening)
6. [Observability & Monitoring](#6-observability--monitoring)
7. [MITRE ATT&CK Integration](#7-mitre-attck-integration)
8. [Testing & Validation](#8-testing--validation)
   - 8.1 [Unit & Integration Tests](#81-unit--integration-tests)
   - 8.2 [Detection Validation (Phase 15)](#82-detection-validation-phase-15)
   - 8.3 [Performance Benchmarks (Phase 16)](#83-performance-benchmarks-phase-16)
   - 8.4 [Security Tests (Phase 17)](#84-security-tests-phase-17)
   - 8.5 [Controlled Security Validation (Phase 21)](#85-controlled-security-validation-phase-21)
9. [Deployment & DevOps](#9-deployment--devops)
10. [Results & Key Findings](#10-results--key-findings)
11. [Limitations & Future Work](#11-limitations--future-work)
12. [Conclusion](#12-conclusion)
13. [Appendix — File Structure](#13-appendix--file-structure)

---

## 1. Executive Summary

This capstone project delivers a **production-grade Security Operations Centre (SOC) platform** for real-time log analysis and suspicious activity detection. The system ingests multi-source log data (authentication, web, firewall, application, system), normalises events into a unified schema, applies a library of 15 rule-based detection algorithms, enriches alerts with MITRE ATT&CK framework mappings and threat intelligence, manages security incidents through a full lifecycle, and surfaces results through an interactive React dashboard and REST API.

**Key outcomes:**
- **180 automated tests** passing across 9 test suites (0 failures)
- **100% recall** on a labelled 132-event validation dataset (TP=62, FP=0, FN=0)
- **8/8 controlled attack scenarios** detected with correct severity assignment
- **15 detection rules** mapped to **8 MITRE ATT&CK tactics**
- Parser throughput: **~340,000 events/second** at 50,000-event scale
- Detection throughput: **~280,000 events/second** at 1,000-event scale
- Fully containerised with Docker Compose and GitHub Actions CI/CD

---

## 2. Introduction & Problem Statement

### 2.1 Background

Modern enterprise networks generate millions of log events daily from heterogeneous sources: Linux PAM/SSH authentication logs, Apache/Nginx web server access logs, firewall deny/allow records, application error logs, and operating-system audit logs. Manually reviewing this volume of data to detect intrusions, brute-force attacks, or insider threats is infeasible.

A Security Information and Event Management (SIEM) system automates this process by:
1. **Ingesting** logs from multiple sources
2. **Normalising** them into a unified schema
3. **Correlating** events to identify patterns indicative of malicious activity
4. **Alerting** security analysts with prioritised, contextualised notifications
5. **Managing** investigation workflows through an incident lifecycle

### 2.2 Project Objectives

| # | Objective | Achieved |
|---|-----------|----------|
| 1 | Multi-source log parsing pipeline | ✅ |
| 2 | Unified event normalisation schema | ✅ |
| 3 | Rule-based detection engine with ≥10 rules | ✅ (15 rules) |
| 4 | Risk scoring and severity classification | ✅ |
| 5 | Threat intelligence enrichment | ✅ |
| 6 | Incident lifecycle management | ✅ |
| 7 | REST API with auto-generated documentation | ✅ |
| 8 | Interactive SOC dashboard | ✅ |
| 9 | HTML and PDF report generation | ✅ |
| 10 | MITRE ATT&CK framework mapping | ✅ |
| 11 | Containerised deployment (Docker) | ✅ |
| 12 | CI/CD pipeline (GitHub Actions) | ✅ |
| 13 | Security hardening (auth, rate-limiting, input validation) | ✅ |
| 14 | Comprehensive automated test suite | ✅ (180 tests) |

### 2.3 Scope

The project is limited to **detection and response tooling** — it is not a full intrusion prevention system (IPS) and does not perform automated remediation. All sample data uses RFC 5737 documentation IP addresses (198.51.100.x / 203.0.113.x) to prevent real-world impact.

---

## 3. System Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA SOURCES                                 │
│  Auth Logs │ Web Logs │ Firewall Logs │ App Logs │ Sys Logs    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  PARSERS    │  src/parsers/
                    │  (Phase 1)  │  AuthParser · WebParser
                    └──────┬──────┘  FWParser · AppParser · SysParser
                           │
                    ┌──────▼──────┐
                    │NORMALISATION│  src/normalization/
                    │  SCHEMA     │  NormalizedEvent dataclass
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  STORAGE    │  src/storage/
                    │  (SQLite)   │  SQLAlchemy ORM
                    └──────┬──────┘
                           │
          ┌────────────────┼──────────────────┐
          │                │                  │
   ┌──────▼──────┐  ┌──────▼──────┐  ┌───────▼───────┐
   │ DETECTION   │  │  THREAT     │  │  REPORTING    │
   │  ENGINE     │  │  INTEL      │  │               │
   │  15 rules   │  │  Feed+DB    │  │  HTML/PDF/JSON│
   └──────┬──────┘  └──────┬──────┘  └───────────────┘
          │                │
   ┌──────▼──────┐         │
   │  INCIDENTS  │◄────────┘
   │  LIFECYCLE  │
   └──────┬──────┘
          │
   ┌──────▼──────────────────┐
   │     FastAPI REST API     │  src/api/  (port 8000)
   │  /events /alerts         │
   │  /incidents /reports     │
   │  /health /metrics /docs  │
   └──────┬──────────────────┘
          │
   ┌──────▼──────────────────┐
   │   React SOC Dashboard   │  frontend/  (port 5173)
   │   Vite + Recharts        │
   └─────────────────────────┘
```

### 3.2 Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Backend API | FastAPI 0.115 | Async-ready, auto-generates OpenAPI docs, Pydantic validation |
| ORM | SQLAlchemy 2.0 | Mature, declarative models, portable across DB engines |
| Database | SQLite 3 | Zero-configuration for a capstone; swap to PostgreSQL via `DATABASE_URL` |
| Frontend | React 18 + Vite | Fast HMR, component-based SOC dashboard |
| Charts | Recharts | Declarative React chart library |
| PDF/HTML Reports | WeasyPrint + Jinja2 | Server-side PDF generation without headless browser |
| Containerisation | Docker + Docker Compose | Reproducible one-command deployment |
| CI/CD | GitHub Actions | Free for public repositories, YAML-driven |
| Testing | pytest 9 | De facto Python testing standard |

---

## 4. Implementation Details

### 4.1 Log Ingestion & Parsing

**Files:** `src/parsers/`, `src/ingestion/`

Five specialised parsers handle different log formats using Python `re` (regex) pattern matching:

| Parser | Module | Log Format | Event Types |
|--------|--------|-----------|-------------|
| Authentication | `authentication_parser.py` | `TIMESTAMP EVENT src=IP user=USER service=SVC` | LOGIN_SUCCESS, LOGIN_FAILED |
| Web | `web_parser.py` | Combined Log Format (Apache/Nginx) | HTTP_REQUEST |
| Firewall | `firewall_parser.py` | `TIMESTAMP ACTION SRC DST PROTO PORT` | FIREWALL_EVENT |
| Application | `application_parser.py` | `TIMESTAMP LEVEL [SVC] MESSAGE` | APP_ERROR, APP_WARN |
| System | `system_parser.py` | `TIMESTAMP HOSTNAME syslog: MESSAGE` | SYSTEM_EVENT |

The ingestion pipeline (`src/ingestion/pipeline.py`) orchestrates discovery, parsing, deduplication by raw log hash, and CSV output. It returns an `IngestionSummary` dataclass with counts for observability.

**Deduplication:** Events with identical `raw_log` content are deduplicated before storage to prevent double-counting from log rotation overlaps.

### 4.2 Normalisation & Storage

**Files:** `src/normalization/schema.py`, `src/storage/`

All parsed events are mapped to the `NormalizedEvent` dataclass:

```python
@dataclass
class NormalizedEvent:
    event_id: str        # Parser-assigned unique ID
    timestamp: str       # ISO-8601 datetime
    event_type: str      # LOGIN_FAILED, HTTP_REQUEST, etc.
    event_category: str  # authentication | web | firewall | application | system
    source_ip: str       # Originating IP address
    username: str        # Associated user account (if applicable)
    service: str         # Targeted service (ssh, http, etc.)
    status: str          # success | failed | error | deny
    raw_log: str         # Original unmodified log line
    # ... 10 further optional fields
```

SQLAlchemy's `EventModel` persists these to SQLite via `src/storage/models.py`. The `import_events` module batch-inserts normalised events in a single transaction.

### 4.3 Detection Engine & Rules

**Files:** `src/detection/`

The detection engine uses a **strategy pattern**: each rule is an independent class implementing a `BaseRule` interface with a single `evaluate(events: List[Event]) -> List[Alert]` method. The `DetectionEngine` applies all registered rules in sequence.

**15 Detection Rules:**

| Rule ID | Name | Category | Severity | Trigger Condition |
|---------|------|----------|----------|-------------------|
| AUTH-001 | Multiple Failed Logins | Authentication | HIGH | ≥5 LOGIN_FAILED from same IP |
| AUTH-002 | Account Lockout Evasion | Authentication | MEDIUM | Mix of failed and access-denied |
| AUTH-003 | Unusual Login Time | Authentication | MEDIUM | Login outside 06:00–22:00 |
| AUTH-004 | Login After Failures | Authentication | CRITICAL | LOGIN_SUCCESS after ≥5 failures |
| AUTH-005 | Password Spraying | Authentication | HIGH | ≥5 failures across ≥3 different users |
| AUTH-006 | Root Login Attempt | Authentication | HIGH | LOGIN_FAILED for root/admin accounts |
| AUTH-007 | Impossible Travel | Authentication | CRITICAL | Same user, different IPs in short window |
| WEB-001 | SQL Injection Attempt | Web | HIGH | SQL keywords in HTTP path/params |
| WEB-002 | Excessive Request Volume | Web | MEDIUM | ≥100 requests in 5 min from same IP |
| WEB-003 | Scanner User-Agent | Web | MEDIUM | Known scanner UA strings (nmap, sqlmap) |
| WEB-004 | Directory Traversal | Web | HIGH | `../` patterns in request paths |
| WEB-005 | Sensitive Path Enumeration | Web | HIGH | Requests to /admin, /.env, /backup etc. |
| FW-001 | Firewall Denial Burst | Firewall | HIGH | ≥5 DENY events from same source |
| APP-001 | Application Error Burst | Application | MEDIUM | ≥5 APP_ERROR in 10 min |
| SYS-001 | Service Failure Burst | System | HIGH | ≥3 service stopped events |

**Alert model** (`src/detection/models/alert.py`) captures: `rule_id`, `severity`, `source_ip`, `description`, `risk_score` (0–100 float), `timestamp`, and MITRE ATT&CK fields.

**Risk Scoring Formula:**

```
risk_score = base_severity_score + frequency_bonus + threat_intel_bonus
```

Where:
- `base_severity_score`: CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20
- `frequency_bonus`: linear with event count, capped at 15
- `threat_intel_bonus`: `confidence × 0.2`, capped at 20

### 4.4 Threat Intelligence

**Files:** `src/threat_intel/`

A CSV-based threat intelligence feed (`data/threat_intel/ip_feed.csv`) stores known malicious IP addresses with:
- IP address (validated against RFC 5737 documentation ranges)
- Threat type (brute_force, phishing, malware, credential stuffing)
- Confidence score (0–100)
- Source label and description

The `feed_loader.py` enforces:
- IP address format validation (Python `ipaddress` stdlib)
- Confidence range validation (0–100 integer)
- Duplicate IP detection (raises `ValueError`)

The `ThreatIntelService` provides `lookup_ip()` and `is_known_threat()` lookups. `enrich_ip()` returns an `EnrichmentResult` with `.matched`, `.risk_bonus`, `.threat_type`, and `.confidence` attributes, allowing downstream risk scoring to remain testable.

### 4.5 Incident Management

**Files:** `src/incidents/`

Alerts above a configurable threshold are promoted to **incidents** with a full lifecycle:

```
OPEN → INVESTIGATING → RESOLVED → CLOSED
```

The `create_incidents` module groups related alerts (same source IP within a 60-minute window) into a single incident to reduce analyst fatigue. Each incident captures: incident ID, title, severity, assigned analyst, status, and linked alert IDs.

### 4.6 REST API Backend

**Files:** `src/api/`

FastAPI serves a versioned REST API at `/api/v1/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/events` | GET | Paginated event listing with filters |
| `/api/v1/alerts` | GET | Active alerts with severity filter |
| `/api/v1/incidents` | GET/POST/PATCH | Incident CRUD and status updates |
| `/api/v1/threat-intel` | GET | IOC lookup |
| `/api/v1/reports` | GET | List and download generated reports |
| `/api/v1/investigation` | POST | Ad-hoc IP investigation |
| `/health` | GET | Simple liveness probe |
| `/health/detailed` | GET | Component health (DB, detection engine, parsers) |
| `/metrics` | GET | In-memory request/event counters |
| `/docs` | GET | Interactive Swagger UI |

Security middleware stack (applied in order):
1. `SecurityHeadersMiddleware` — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
2. `RateLimitMiddleware` — sliding window, 100 req/60s per IP
3. `APIKeyHeader` — `X-API-Key` on protected mutation endpoints

### 4.7 SOC Dashboard Frontend

**Files:** `frontend/`

A React 18 single-page application built with Vite provides:

- **Overview panel** — event counts, alert summary, severity distribution donut chart
- **Events table** — searchable, sortable log event listing
- **Alerts panel** — active alerts with rule ID, severity badge, risk score, and source IP
- **Incidents view** — lifecycle management with status change controls
- **Threat Intel panel** — IOC listing and IP lookup
- **Reports panel** — download links for generated HTML/PDF reports

The frontend communicates with the FastAPI backend via the Vite dev-server proxy (`/api → http://127.0.0.1:8000`).

### 4.8 Reporting

**Files:** `src/reporting/`

The `generate_report` module produces three output artefacts in `reports/generated/`:

| Format | File | Contents |
|--------|------|----------|
| HTML | `security_report.html` | Full styled report with embedded charts |
| PDF | `security_report.pdf` | Print-ready version via WeasyPrint |
| JSON | `security_report.json` | Machine-readable summary for downstream tooling |

Reports include: executive summary, event statistics, top source IPs, alert breakdown by rule and severity, incident status distribution, and threat intelligence hits.

---

## 5. Security Hardening

**Files:** `src/api/security/`

Phase 17 implemented five layers of hardening:

### 5.1 API Authentication

The `X-API-Key` header is validated against an environment variable (`API_KEY`). Two role tiers are supported via separate keys (`API_KEY` / `ADMIN_API_KEY`). Keys are loaded via `lru_cache` to avoid repeated env reads. The default development key (`dev-insecure-key-change-in-prod`) must be replaced in production.

### 5.2 Rate Limiting

`RateLimitMiddleware` uses an in-memory sliding window: each IP's request timestamps are stored in a `defaultdict(list)`. Requests older than 60 seconds are evicted on each check. Clients exceeding 100 requests/60s receive HTTP 429.

### 5.3 Input Validation

`input_validator.py` blocks:
- SQL injection characters (`'`, `"`, `;`, `\`)
- Path traversal sequences (`../`)
- HTML/script tags (`<...>`)
- Null bytes (`%00`)
- Strings exceeding 500 characters

### 5.4 Security Headers

`SecurityHeadersMiddleware` attaches:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 5.5 Secrets Management

- `.env` is gitignored; `.env.example` documents required variables
- `pip audit` and `npm audit` outputs are stored in `reports/security/`
- GitHub Actions CI includes a step that fails if `.env` is tracked by git

---

## 6. Observability & Monitoring

**Files:** `src/monitoring/`

Phase 19 added three observability layers:

### 6.1 Structured Logging

`logging_config.py` configures dual-sink logging:
- **Console** (INFO+) — for development and container stdout
- **Rotating file** (WARNING+) — `logs/security_analytics.log`, 10 MB × 5 backups

### 6.2 Health Checks

`health.py` probes three subsystems and reports individual + overall status:
- **Database** — executes `SELECT 1` via SQLAlchemy
- **Detection engine** — loads the rule library and counts rules
- **Parsers** — imports the authentication parser module

The `/health/detailed` endpoint returns:
```json
{
  "status": "healthy",
  "timestamp": "2026-10-21T14:00:00Z",
  "components": {
    "database": {"status": "healthy", "detail": "Connection OK"},
    "detection_engine": {"status": "healthy", "rule_count": 15},
    "parser": {"status": "healthy"}
  }
}
```

### 6.3 In-Memory Metrics

`MetricsStore` (thread-safe via `threading.RLock`) tracks:
- `events_processed_total`
- `alerts_generated_total`
- `incidents_created_total`
- `api_requests_total`
- `api_request_avg_duration_s` (rolling 1000-sample window)

> [!NOTE]
> `RLock` (reentrant lock) is used instead of `Lock` to prevent self-deadlock when `snapshot()` calls `get_api_avg_duration()` — both methods acquire the same lock.

---

## 7. MITRE ATT&CK Integration

**Files:** `src/detection/mitre/`

All 15 detection rules are mapped to the MITRE ATT&CK Enterprise Matrix:

| Tactic | Rules | Techniques |
|--------|-------|-----------|
| Credential Access (TA0006) | AUTH-001, AUTH-004, AUTH-005, AUTH-006 | T1110 (Brute Force) |
| Discovery (TA0007) | WEB-001, WEB-003, WEB-005 | T1046 (Network Service Discovery) |
| Defense Evasion (TA0005) | AUTH-002, SYS-001 | T1078, T1562 |
| Impact (TA0040) | WEB-002, APP-001 | T1498, T1489 |
| Persistence (TA0003) | AUTH-003 | T1078 |
| Lateral Movement (TA0008) | AUTH-007 | T1550 |
| Initial Access (TA0001) | WEB-004 | T1190 |
| Reconnaissance (TA0043) | FW-001 | T1595 |

The `enrich_alert_with_mitre()` function adds `mitre_tactic`, `mitre_technique`, `mitre_technique_id`, `mitre_subtechnique`, `mitre_subtechnique_id`, and `mitre_url` fields to every generated alert dict. This enables:
- Standardised alert reporting aligned with industry vocabulary
- Filtering alerts by ATT&CK tactic in the API and dashboard
- Evidence of detection coverage during security audits

---

## 8. Testing & Validation

### 8.1 Unit & Integration Tests

**Total: 180 tests, 0 failures**

| Test Suite | File Location | Tests | Focus |
|------------|--------------|-------|-------|
| Parsers | `tests/parsers/` | 20 | Regex correctness, edge cases |
| Detection | `tests/detection/` | 25 | Rule triggering, threshold logic |
| Storage | `tests/storage/` | 15 | ORM CRUD, deduplication |
| Security | `tests/security/` | 35 | Auth, rate limiting, input validation |
| Monitoring | `tests/monitoring/` | 14 | Health checks, metrics thread safety |
| MITRE | `tests/mitre/` | 13 | Mapping completeness, enrichment |
| Deployment | `tests/deployment/` | 8 | Dockerfile and CI config presence |
| Validation | `tests/validation/` | 14 | Rule detection end-to-end |
| Threat Intel | `tests/threat_intel/` | 10 | Feed loading, IP lookup, enrichment |
| Integration | `tests/integration/` | 5 | Full pipeline end-to-end |
| Unit | `tests/unit/` | 21 | Cross-module unit tests |

### 8.2 Detection Validation (Phase 15)

A **132-event labelled dataset** (70 normal + 62 suspicious) was run through the complete detection pipeline:

| Metric | Value |
|--------|-------|
| True Positives | 62 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 70 |
| **Accuracy** | **100%** |
| **Precision** | **100%** |
| **Recall** | **100%** |
| **F1 Score** | **1.0** |

> [!NOTE]
> 100% scores reflect controlled test data designed to trigger rules deterministically. Real-world deployments with unseen traffic will exhibit lower precision due to false positives from legitimate automated traffic.

### 8.3 Performance Benchmarks (Phase 16)

All benchmarks use in-memory synthetic data — no disk or network I/O — to measure pure algorithmic throughput.

**Parsing Throughput:**

| Dataset Size | Time (s) | Events/sec | Memory (MB) |
|-------------|----------|-----------|------------|
| 1,000 | 0.003 | 353,719 | 0.4 |
| 10,000 | 0.030 | 331,876 | 4.2 |
| 50,000 | 0.148 | 338,093 | 20.9 |

**Detection Throughput:** ~283,000 events/second at 1,000-event scale.

**SQLite Insertion:** ~12,000 events/second (I/O bound; in-memory SQLite).

**Scaling:** Parser time scales near-linearly with dataset size (ratio < 20× for 10× data increase), confirming O(n) complexity with no unexpected algorithmic degradation.

### 8.4 Security Tests (Phase 17)

35 automated security tests covering:
- SQL injection, path traversal, XSS, null byte, oversized input → all blocked (HTTP 422)
- Rate limiter → HTTP 429 after 100 requests/minute
- `.env` not tracked in git → verified via `git ls-files`
- API key config → returns non-empty string from environment

### 8.5 Controlled Security Validation (Phase 21)

8 adversarial attack scenarios were injected as synthetic event streams and evaluated by the detection engine:

| Scenario | Attack Pattern | Target Rule | Expected Severity | Result |
|----------|---------------|-------------|------------------|--------|
| CV-001 | Multiple failed SSH logins | AUTH-001 | HIGH | ✅ PASS |
| CV-002 | Password spraying across accounts | AUTH-005 | HIGH | ✅ PASS |
| CV-003 | Successful login after failures | AUTH-004 | CRITICAL | ✅ PASS |
| CV-004 | Sensitive path enumeration | WEB-005 | HIGH | ✅ PASS |
| CV-005 | Excessive HTTP request volume | WEB-002 | MEDIUM | ✅ PASS |
| CV-006 | Firewall denial burst | FW-001 | HIGH | ✅ PASS |
| CV-007 | Application error burst | APP-001 | MEDIUM | ✅ PASS |
| CV-008 | Service failure burst | SYS-001 | HIGH | ✅ PASS |

**Overall: 8/8 PASS — 100% True Positive Rate, 0 False Negatives**

---

## 9. Deployment & DevOps

**Files:** `docker/`, `docker-compose.yml`, `.github/workflows/ci.yml`

### 9.1 Docker Containerisation

Two Docker images:

**Backend** (`docker/backend.Dockerfile`):
- Base: `python:3.12-slim`
- Installs dependencies from `requirements.txt`
- Exposes port 8000
- Entrypoint: `uvicorn src.api.main:app`

**Frontend** (`docker/frontend.Dockerfile`):
- Multi-stage build:
  - Stage 1: `node:20-alpine` — `npm install && npm run build`
  - Stage 2: `nginx:alpine` — serves static `dist/` output
- Nginx reverse-proxies `/api/` requests to the backend service

### 9.2 Docker Compose Orchestration

`docker-compose.yml` defines:
- Backend with a healthcheck (`curl /health`) and `./data` bind mount for SQLite persistence
- Frontend `depends_on: backend` with a 30-second healthcheck interval
- Shared `log-analysis-network` bridge network

### 9.3 CI/CD (GitHub Actions)

`.github/workflows/ci.yml` runs on every push to `main`/`develop` and every PR:

1. **Test job** — Python 3.12, `pip install -r requirements.txt`, `pytest`, `flake8` lint
2. **Security job** — verifies `.env` is not tracked by git
3. **Docker build job** — builds the backend Docker image to catch build-time errors

---

## 10. Results & Key Findings

### 10.1 Summary Metrics

| Metric | Value |
|--------|-------|
| Detection rules implemented | 15 |
| MITRE ATT&CK tactics covered | 8 |
| Automated tests passing | 180 |
| Detection recall (labelled dataset) | 100% |
| Controlled scenario pass rate | 8/8 (100%) |
| Parser throughput (50k events) | ~338k events/s |
| API endpoints | 15+ |
| Docker images | 2 (backend + frontend) |
| CI/CD pipeline jobs | 3 (test, security, docker-build) |

### 10.2 Technical Decisions & Rationale

**SQLite over PostgreSQL:** The project uses SQLite for zero-configuration local development. The `DATABASE_URL` environment variable allows switching to PostgreSQL by changing a single string — all SQLAlchemy ORM code is DB-agnostic.

**Rule-based over ML detection:** Rule-based detection provides **explainability** — analysts can trace exactly why an alert fired. ML anomaly detection (Phase 7) was implemented as an additive layer, not a replacement, since rule-based detection achieves perfect recall on known attack patterns.

**RLock in MetricsStore:** Python's `threading.Lock` is non-reentrant. When `snapshot()` calls `get_api_avg_duration()`, both acquire the same lock — this would deadlock with `Lock`. `RLock` allows the same thread to acquire the lock multiple times.

**SimpleNamespace for test events:** Benchmark and controlled validation scenarios use `SimpleNamespace` objects instead of full SQLAlchemy models, decoupling performance measurement from database I/O.

---

## 11. Limitations & Future Work

| Limitation | Description | Suggested Future Work |
|-----------|-------------|----------------------|
| SQLite scalability | Concurrent writes serialise | Migrate to PostgreSQL for production |
| In-memory rate limiter | Resets on restart, not shared across instances | Redis-backed rate limiting |
| Static threat feed | CSV requires manual updates | Integrate live OSINT feeds (OTX, VirusTotal) |
| Rule threshold hardcoding | Thresholds embedded in rule files | Admin UI for configurable thresholds |
| No streaming ingestion | Batch pipeline only | Apache Kafka integration for real-time streaming |
| 100% test dataset scores | Controlled data; real-world will differ | Evaluate against production log samples |
| No TLS in development | HTTP only | Add Let's Encrypt / Caddy in production Docker config |
| Frontend has no auth | API key only on backend | Add JWT-based frontend authentication |

---

## 12. Conclusion

This capstone project successfully delivers a fully functional, production-quality SOC platform for log analysis and suspicious activity detection. The system demonstrates:

1. **Correctness** — 100% recall on labelled data, 8/8 controlled attack scenarios detected
2. **Performance** — 338,000 events/second parsing throughput, O(n) scaling
3. **Security** — authentication, rate limiting, input validation, security headers, no committed secrets
4. **Maintainability** — 180 automated tests, modular architecture, Docker containerisation
5. **Standards alignment** — 15 rules mapped to 8 MITRE ATT&CK tactics

The platform demonstrates the feasibility of building a comprehensive security analytics system using Python's scientific and web ecosystem, and provides a strong foundation for extension with streaming ingestion, ML-based anomaly detection, and production database backends.

---

## 13. Appendix — File Structure

```
Log_Analysis_Suspicious_Activity_Detection/
├── README.md                          # Setup, run, and test instructions
├── requirements.txt                   # Runtime dependencies
├── requirements-lock.txt              # Pinned dependency versions
├── .gitignore                         # Excludes .env, venv, __pycache__, *.db
├── .env.example                       # Required environment variable template
├── docker-compose.yml                 # Multi-service orchestration
│
├── src/
│   ├── api/                           # FastAPI application
│   │   ├── main.py                    # App factory, middleware, startup
│   │   ├── routes/                    # Route handlers (events, alerts, incidents…)
│   │   ├── schemas.py                 # Pydantic request/response models
│   │   └── security/                  # Auth, rate limiter, headers, input validation
│   ├── parsers/                       # Log parsers (auth, web, firewall, app, sys)
│   ├── normalization/                 # NormalizedEvent schema
│   ├── ingestion/                     # Pipeline, log collector, deduplicator
│   ├── storage/                       # SQLAlchemy models, DB session, repositories
│   ├── detection/                     # Detection engine, 15 rules, MITRE mapping
│   ├── threat_intel/                  # Feed loader, service, enrichment
│   ├── incidents/                     # Incident creation and lifecycle
│   ├── reporting/                     # HTML/PDF/JSON report generation
│   ├── monitoring/                    # Logging, health checks, metrics
│   └── validation/                    # Controlled scenario generator and runner
│
├── frontend/                          # React + Vite SOC dashboard
│   ├── src/                           # Components, pages, API client
│   └── package.json
│
├── tests/                             # 180 automated tests
│   ├── conftest.py                    # Shared fixtures
│   ├── detection/                     # Rule and engine tests
│   ├── security/                      # Hardening tests
│   ├── monitoring/                    # Observability tests
│   ├── mitre/                         # ATT&CK mapping tests
│   ├── validation/                    # Controlled scenario tests
│   ├── threat_intel/                  # Feed and service tests
│   ├── deployment/                    # Config presence tests
│   ├── integration/                   # End-to-end pipeline tests
│   └── unit/                          # Cross-module unit tests
│
├── data/
│   ├── raw/                           # Sample log files (5 categories)
│   └── threat_intel/ip_feed.csv       # RFC 5737 synthetic threat feed
│
├── reports/
│   ├── generated/                     # HTML, PDF, JSON security reports
│   ├── validation/                    # Confusion matrix, rule validation matrix
│   ├── performance/                   # Benchmark results, scalability chart
│   ├── security/                      # Hardening report, audit outputs
│   ├── mitre/                         # ATT&CK coverage report
│   ├── monitoring/                    # Monitoring report
│   └── deployment/                    # Deployment report
│
├── docker/
│   ├── backend.Dockerfile
│   ├── frontend.Dockerfile
│   └── nginx.conf
│
├── docs/
│   ├── project_report.md              # This document
│   ├── deployment.md                  # Docker deployment guide
│   └── monitoring.md                  # Observability guide
│
└── .github/
    └── workflows/ci.yml               # GitHub Actions CI/CD pipeline
```

---

*This report was generated as part of the capstone submission for the Log Analysis & Suspicious Activity Detection Platform project.*
