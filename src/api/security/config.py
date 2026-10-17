"""
Security configuration loaded from environment variables.

Secrets live in `.env` (never committed). `.env.example` documents the keys.
"""
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(_PROJECT_ROOT / ".env")

DEV_ANALYST_KEY = "dev-insecure-key-change-in-prod"
DEV_ADMIN_KEY = "dev-insecure-admin-key-change-in-prod"


@lru_cache(maxsize=1)
def get_api_key() -> str:
    """Analyst (read) API key."""
    return os.environ.get("API_KEY", DEV_ANALYST_KEY)


@lru_cache(maxsize=1)
def get_admin_api_key() -> str:
    """Admin (write) API key."""
    return os.environ.get("ADMIN_API_KEY", DEV_ADMIN_KEY)


def get_app_env() -> str:
    return os.environ.get("APP_ENV", "development").lower()


def is_production() -> bool:
    return get_app_env() == "production"


def is_rate_limit_disabled() -> bool:
    return os.environ.get("RATE_LIMIT_DISABLED", "").lower() in {"1", "true", "yes"}


def get_cors_origins() -> list[str]:
    raw = os.environ.get(
        "ALLOW_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or ["http://localhost:5173"]


def clear_api_key_cache() -> None:
    """Clear lru_cache — useful in tests."""
    get_api_key.cache_clear()
    get_admin_api_key.cache_clear()
