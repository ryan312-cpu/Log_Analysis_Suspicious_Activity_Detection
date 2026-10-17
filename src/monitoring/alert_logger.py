import logging
from typing import Optional

from src.monitoring.logging_config import get_logger

logger = get_logger("security.alerts")


def log_alert_generated(
    rule_id: str,
    severity: str,
    source_ip: Optional[str] = None,
    description: Optional[str] = None,
):
    """Log a security detection alert with appropriate log level."""
    msg = f"Alert generated: rule={rule_id} severity={severity}"
    if source_ip:
        msg += f" source_ip={source_ip}"
    if description:
        msg += f" desc='{description}'"

    if severity.upper() in ("CRITICAL", "HIGH"):
        logger.warning(msg)
    else:
        logger.info(msg)


def log_detection_run(event_count: int, alert_count: int, duration_s: float):
    """Log the results of a detection pipeline run."""
    logger.info(
        f"Detection cycle complete: events={event_count} alerts={alert_count} duration={duration_s:.4f}s"
    )


def log_parser_error(source: str, error: str):
    """Log a parsing or normalization failure."""
    logger.error(f"Parser error on source={source}: {error}")
