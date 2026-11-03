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

---

## 7. Cloud Demo Deployment (Render + Vercel)

The project can be demonstrated as two services: the FastAPI backend on Render
and the React dashboard on Vercel. The repository includes a Render Blueprint
at `render.yaml` and Vercel settings at `frontend/vercel.json`.

> **Demo-only security and data warning:** `VITE_API_KEY` is compiled into the
> browser bundle and is visible to anyone using the dashboard. Use only the
> generated, read-only `API_KEY` for this demo and sample data. Never put
> `ADMIN_API_KEY` in Vercel or the frontend. The free Render service may sleep
> when idle and its filesystem is ephemeral; database changes and uploaded
> data may be lost after a restart or redeploy. Do not use this setup for
> sensitive data or production workloads.

### A. Deploy the API to Render

1. Push the repository to GitHub and sign in to [Render](https://render.com/).
2. Select **New + → Blueprint**, connect this repository, and deploy the
   blueprint from the repository root. Render reads `render.yaml`, installs
   the Python requirements, prepares sample data, and starts Uvicorn.
3. In the `log-analysis-api` service's **Environment** settings, verify:
   - `APP_ENV` is `production`.
   - `API_KEY` and `ADMIN_API_KEY` are generated by Render. Keep the admin key
     private; it is not needed by the dashboard.
   - `ALLOW_ORIGINS` contains the exact Vercel site origin, without a trailing
     slash. The blueprint is preconfigured for the repository's current Vercel
     demo URL. Replace it if you use another Vercel URL or a custom domain.
4. Wait for the service deploy to finish and copy its public URL, for example
   `https://log-analysis-api.onrender.com`.
5. Check `https://<render-service>.onrender.com/health` and
   `https://<render-service>.onrender.com/docs`. The health endpoint should
   return a healthy status; the docs page should show the API routes.

### B. Deploy the dashboard to Vercel

1. In [Vercel](https://vercel.com/), select **Add New → Project** and import
   this GitHub repository.
2. Set **Root Directory** to `frontend`. Use the Vite defaults:
   - Build command: `npm run build`
   - Output directory: `dist`
3. Add these environment variables for the Production environment:

   | Name | Value |
   | --- | --- |
   | `VITE_API_BASE_URL` | `https://<render-service>.onrender.com/api/v1` |
   | `VITE_API_KEY` | The Render `API_KEY` value |

   Replace the example hostname with the URL copied from Render. Keep the
   `/api/v1` suffix. These Vite variables are embedded at build time, so add
   them before the initial deployment and redeploy after changing them.
4. Deploy the project and copy its production origin, such as
   `https://<project>.vercel.app`.
5. Return to Render and set `ALLOW_ORIGINS` to that exact origin. If you have
   additional Vercel preview or custom domains, list each allowed origin as a
   comma-separated value. Save the setting and redeploy/restart the API if
   Render does not do so automatically.
6. Open the Vercel URL and confirm that the dashboard loads events and alerts.

### C. Verify and troubleshoot

- **API health:** Open the Render `/health` endpoint directly.
- **Dashboard API connection:** In the browser's developer tools, check for
  401, 404, or CORS errors. A 401 usually means `VITE_API_KEY` does not match
  Render's `API_KEY`; a 404 usually means `VITE_API_BASE_URL` is missing
  `/api/v1`; a CORS error usually means the Vercel origin is absent from
  `ALLOW_ORIGINS`.
- **First request is slow:** A free Render instance may be waking from sleep.
  Retry after the service finishes starting.
- **Updated Vercel environment values:** Trigger a new Vercel deployment so
  the build picks up the new values.
- **Updated CORS or backend environment values:** Restart/redeploy the Render
  service after saving them.

Once GitHub deployments are connected, pushes to the configured production
branch trigger new deployments on both providers. Check each provider's
deployment logs if a build or startup fails.
