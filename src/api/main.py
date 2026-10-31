import os
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.api.routes import alerts, events, incidents, investigation, reports, threat_intel
from src.api.security.config import get_cors_origins, is_production
from src.api.security.rate_limiter import RateLimitMiddleware
from src.api.security.secure_headers import SecurityHeadersMiddleware
from src.monitoring.logging_config import configure_logging
from src.monitoring.metrics import get_metrics
from src.storage.database import initialize_database

# Configure platform structured logging
configure_logging()

initialize_database()

_disable_docs = os.environ.get("DISABLE_DOCS", "").lower() in {"1", "true", "yes"}
_docs = None if _disable_docs else "/docs"
_redoc = None if _disable_docs else "/redoc"
_openapi = None if _disable_docs else "/openapi.json"

app = FastAPI(
    title="Log Analysis & Suspicious Activity Detection API",
    description=(
        "Security analytics and investigation API "
        "for log analysis, detection and alert management."
    ),
    version="1.0.0",
    docs_url=_docs,
    redoc_url=_redoc,
    openapi_url=_openapi,
)

# ── Metrics Middleware ────────────────────────────────────────────────────────
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start
    get_metrics().record_api_request(duration)
    return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)



@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None) or {},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request payload"},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, (HTTPException, StarletteHTTPException, RequestValidationError)):
        raise exc
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


app.include_router(events.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(investigation.router, prefix="/api/v1")
app.include_router(threat_intel.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/")
def root_index():
    return {
        "service": "Log Analysis and Suspicious Activity Detection Platform API",
        "status": "running",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/health",
        "health_detailed": "/health/detailed",
        "metrics": "/metrics",
        "endpoints": {
            "events": "/api/v1/events",
            "alerts": "/api/v1/alerts",
            "incidents": "/api/v1/incidents",
            "threat_intel": "/api/v1/threat-intel",
            "reports": "/api/v1/reports"
        }
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "security-analytics-api",
    }


@app.get("/health/detailed")
def health_check_detailed():
    """Extended health check with component status."""
    try:
        from src.monitoring.health import get_full_health
        return get_full_health()
    except ImportError:
        return {
            "status": "healthy",
            "service": "security-analytics-api",
            "monitoring": "not configured",
        }


@app.get("/metrics")
def metrics_endpoint():
    """Return current application telemetry metrics snapshot."""
    return get_metrics().snapshot()

