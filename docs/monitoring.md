# Observability & Monitoring Architecture Guide

This document specifies the logging, health checking, and telemetry metrics collection subsystems for the **Log Analysis & Suspicious Activity Detection Platform**.

---

## 1. Overview

Observability in the security analytics platform comprises three primary telemetry domains:
1. **Structured Logging:** Centralized application and audit logging with rotation and log levels.
2. **Subsystem Health Monitoring:** Component-level diagnostic probes (Database, Detection Engine, Parsers).
3. **Telemetry Metrics:** In-memory, thread-safe metric counters and latency tracking exposed via `/metrics`.

```
                    ┌───────────────────────────────┐
                    │       External Ingress        │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                     FastAPI Application Gateway
                      (src/api/main.py)
                        ├── Metrics Middleware ─────────► [ MetricsStore ]
                        ├── /health (Liveness)                │
                        ├── /health/detailed (Readiness)      │
                        └── /metrics (Telemetry) ◄────────────┘
                                    │
                   ┌────────────────┴────────────────┐
                   ▼                                 ▼
      [ Subsystem Health Probes ]        [ Structured Audit Logs ]
      ├── Database (SQLite SELECT 1)     ├── Console (stdout INFO+)
      ├── Detection Engine (Rules > 15)  └── logs/security_analytics.log
      └── Parsers (Parser Registry)          (RotatingFileHandler 10MB)
```

---

## 2. Structured Logging (`src/monitoring/logging_config.py`)

- **Root Logger:** Formatted as `%(asctime)s %(levelname)-8s [%(name)s] %(message)s`.
- **Console Stream:** Outputs `INFO` and above to `sys.stdout`.
- **Rotating File Handler:**
  - File target: `logs/security_analytics.log`
  - Max size: 10 MB per file, keeping up to 5 historical rotations.
  - Level: `WARNING` and above for forensic alerts, parser anomalies, and security events.

### Specialized Alert Logger (`src/monitoring/alert_logger.py`)
- Provides domain-specific logging functions:
  - `log_alert_generated(rule_id, severity, source_ip)`
  - `log_detection_run(event_count, alert_count, duration_s)`
  - `log_parser_error(source, error)`

---

## 3. Subsystem Health Probes (`src/monitoring/health.py`)

The platform distinguishes between basic liveness and deep readiness:

### 3.1 Liveness Probe (`GET /health`)
- Fast, non-blocking check returning `{"status": "healthy", "service": "security-analytics-api"}`.
- Used by Docker and Kubernetes container runtimes to detect service crashes.

### 3.2 Readiness & Component Probe (`GET /health/detailed`)
- Performs active diagnostic inspections:
  - **Database:** Executes `SELECT 1` on the SQLAlchemy engine.
  - **Detection Engine:** Queries `get_rule_library()` to confirm all detection rules are loaded.
  - **Parser Engine:** Validates the parser registry is responsive.
- Returns comprehensive JSON:
```json
{
  "status": "healthy",
  "timestamp": "2026-10-17T15:10:00.000000Z",
  "components": {
    "database": {"status": "healthy", "detail": "Database connection OK"},
    "detection_engine": {"status": "healthy", "rule_count": 15, "detail": "15 detection rules registered"},
    "parser": {"status": "healthy", "detail": "Log parsers loaded successfully"}
  }
}
```

---

## 4. Telemetry Metrics (`src/monitoring/metrics.py`)

Metrics are managed in-memory via the thread-safe `MetricsStore` using re-entrant synchronization (`threading.RLock`).

### Available Metrics via `GET /metrics`

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `events_processed_total` | Counter | Total volume of normalized events processed |
| `alerts_generated_total` | Counter | Total security alerts raised by detection rules |
| `incidents_created_total` | Counter | Total incident records created from alerts |
| `parser_errors_total` | Counter | Count of malformed or unparseable raw log records |
| `detection_errors_total` | Counter | Count of runtime exceptions during rule evaluation |
| `api_requests_total` | Counter | Aggregate HTTP requests served across all endpoints |
| `api_request_avg_duration_s` | Gauge | Rolling average latency (seconds) of recent API requests |
