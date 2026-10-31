"""Utility to automatically populate sample security events, alerts, threat intel,
and incidents if the database is empty (e.g. on Render container cold-start).
"""
import logging
from src.storage.database import get_session
from src.storage.models import EventModel

logger = logging.getLogger(__name__)

def ensure_initial_seed():
    """Check if the database has events; if not, run the pipeline to populate it."""
    session = get_session()
    try:
        count = session.query(EventModel).count()
        if count > 0:
            logger.info("Database already contains %d events. Skipping seed.", count)
            return

        logger.info("Database is empty. Automatically seeding sample logs and detection pipeline...")
        from src.parsers.run_parsers import main as run_parsers
        from src.storage.import_events import main as import_events
        from src.detection.run_detection import main as run_detection
        from src.threat_intel.import_feed import main as import_feed
        from src.incidents.create_incidents import main as create_incidents

        run_parsers()
        import_events()
        run_detection()
        import_feed()
        create_incidents()
        logger.info("Auto-seeding pipeline completed successfully.")
    except Exception as exc:
        logger.warning("Auto-seeding could not complete: %s", exc)
    finally:
        session.close()
