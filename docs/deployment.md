# Deployment & Operations Guide

This guide details the containerization, orchestration, and production deployment architecture for the **Log Analysis & Suspicious Activity Detection Platform**.

---

## 1. Architecture Overview

The system is containerized as a decoupled multi-tier service:

```
                           [ Web Browser ]
                                  │
                                  ▼
                         Host Port 80 (HTTP)
                                  │
                    ┌─────────────┴─────────────┐
                    │    log-analysis-frontend  │
                    │    (Nginx Reverse Proxy)  │
                    └─────────────┬─────────────┘
                                  │
                   Proxy /api/*   │   Proxy /health
                                  ▼
                    ┌───────────────────────────┐
                    │    log-analysis-backend   │
                    │      (FastAPI Engine)     │
                    │         Port 8000         │
                    └─────────────┬─────────────┘
                                  │
                        Persistent Bind Mounts
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
             /app/data (SQLite)        /app/logs (Audit Logs)
```

### Components
1. **Frontend (`log-analysis-frontend`):**
   - Built with Node 20 / Vite React SPA.
   - Served via Alpine Nginx.
   - Automatically handles client-side routes (`try_files`) and proxies API and health check traffic to the backend service.
2. **Backend (`log-analysis-backend`):**
   - Python 3.12-slim runtime executing FastAPI via Uvicorn.
   - Encapsulates log parsing, rule evaluation, anomaly detection, investigation graph generation, and threat intelligence.
3. **Data Persistence:**
   - Host directory `./data` mapped to `/app/data` (stores SQLite analytical database).
   - Host directory `./logs` mapped to `/app/logs` (stores application and forensic logs).

---

## 2. Prerequisites

- **Docker:** Engine 24.0.0 or later
- **Docker Compose:** v2.20.0 or later
- **Git:** 2.30+

---

## 3. Quick Start

### Step 1: Clone and Configure Environment
Copy the configuration template:
```bash
cp .env.example .env
```
Generate random secrets for production in `.env`:
```env
API_KEY=c3f81e9b-42d1-4e78-a0e2-76bf8d13a84e
ADMIN_API_KEY=a72d9e11-409b-4e12-8ef9-8b09f12d4a21
APP_ENV=production
```

### Step 2: Build and Start Containers
Launch the stack in detached mode:
```bash
docker compose up -d --build
```

### Step 3: Verify Container Health
```bash
docker compose ps
```
Both `log-analysis-backend` and `log-analysis-frontend` should report status `Up (healthy)`.

---

## 4. Operational Endpoints

| Service | Target URL | Description |
| :--- | :--- | :--- |
| **Web Dashboard** | `http://localhost/` | React investigation UI |
| **Direct API** | `http://localhost:8000/docs` | OpenAPI / Swagger interactive documentation |
| **Proxied API** | `http://localhost/api/v1/health` | Gateway proxy routing check |
| **System Health** | `http://localhost:8000/health` | Container health probe |

---

## 5. Maintenance & Management

### Viewing Live Logs
```bash
# All services
docker compose logs -f

# Backend only
docker compose logs -f backend
```

### Stopping the Stack
```bash
docker compose down
```

### Resetting Data Volumes
```bash
docker compose down -v
```

---

## 6. Continuous Integration (CI/CD)

The repository includes a GitHub Actions pipeline in `.github/workflows/ci.yml` that automatically:
1. Runs all unit, detection, performance, and security test suites on Python 3.12.
2. Checks git repository history to ensure zero `.env` secrets have been leaked.
3. Validates Docker Compose files and container configs.
