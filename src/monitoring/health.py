import logging
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import text

logger = logging.getLogger(__name__)


def check_database_health() -> Dict[str, Any]:
    """Test connectivity to SQLite database."""
    session = None
    try:
        from src.storage.database import get_session
        session = get_session()
        session.execute(text("SELECT 1"))
        return {"status": "healthy", "detail": "Database connection OK"}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {"status": "unhealthy", "detail": str(e)}
    finally:
        if session is not None:
            session.close()


def check_detection_engine_health() -> Dict[str, Any]:
    """Verify detection rule registry is loaded and functional."""
    try:
        from src.detection.rules.rule_registry import get_rule_library
        rules = get_rule_library()
        return {
            "status": "healthy",
            "rule_count": len(rules),
            "detail": f"{len(rules)} detection rules registered",
        }
    except Exception as e:
        logger.error(f"Detection engine health check failed: {e}")
        return {"status": "unhealthy", "detail": str(e)}


def check_parser_health() -> Dict[str, Any]:
    """Verify log parsers are accessible."""
    try:
        from src.parsers.base_parser import BaseParser
        return {
            "status": "healthy",
            "detail": "Log parsers loaded successfully",
        }
    except Exception as e:
        logger.error(f"Parser health check failed: {e}")
        return {"status": "degraded", "detail": str(e)}


def get_full_health() -> Dict[str, Any]:
    """
    Aggregate all subsystem health checks into an overall status:
    - 'healthy': all components healthy
    - 'degraded': one or more components degraded (none unhealthy)
    - 'unhealthy': one or more components unhealthy
    """
    db_health = check_database_health()
    engine_health = check_detection_engine_health()
    parser_health = check_parser_health()

    components = {
        "database": db_health,
        "detection_engine": engine_health,
        "parser": parser_health,
    }

    if any(c.get("status") == "unhealthy" for c in components.values()):
        overall = "unhealthy"
    elif any(c.get("status") == "degraded" for c in components.values()):
        overall = "degraded"
    else:
        overall = "healthy"

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }
