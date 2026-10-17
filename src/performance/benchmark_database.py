"""
Benchmark SQLite database insertion at different dataset sizes.
Uses an in-memory SQLite database to avoid touching production data.
"""
import sys
import time
from typing import List

sys.path.insert(0, ".")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATASET_SIZES = [1_000, 10_000, 50_000, 100_000]


def _get_in_memory_session():
    """Create a fresh in-memory SQLite session with EventModel schema."""
    from src.storage.models import EventModel
    from src.storage.database import Base

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return Session(), engine


def _make_event_model(i: int):
    from src.storage.models import EventModel
    return EventModel(
        event_id=f"DB-BENCH-{i:08d}",
        timestamp=f"2026-09-25 10:{(i // 3600) % 60:02d}:{i % 60:02d}",
        event_type="LOGIN_FAILED",
        event_category="authentication",
        source_ip=f"10.0.{(i // 256) % 256}.{i % 256}",
        username=f"user_{i % 200}",
        service="ssh",
        status="failed",
        source_type="authentication",
        raw_log=f"2026-09-25 LOGIN_FAILED src=10.0.0.{i % 255} user=user_{i % 200}",
    )


def run_database_benchmark(sizes: List[int] = None) -> List[dict]:
    """Benchmark DB insertion for different dataset sizes."""
    if sizes is None:
        sizes = DATASET_SIZES

    results = []
    for n in sizes:
        session, engine = _get_in_memory_session()

        try:
            # Build all EventModel objects first (not counted in timing)
            rows = [_make_event_model(i) for i in range(n)]

            # Time only the insert + commit
            t0 = time.perf_counter()
            # Bulk insert in batches of 1000 for realism
            batch_size = 1000
            for start in range(0, n, batch_size):
                session.bulk_save_objects(rows[start : start + batch_size])
            session.commit()
            elapsed = time.perf_counter() - t0

            # Verify row count
            count = session.execute(text("SELECT COUNT(*) FROM events")).scalar()

        finally:
            session.close()
            engine.dispose()

        result = {
            "benchmark": "database",
            "dataset_size": n,
            "insertion_time_s": round(elapsed, 4),
            "events_per_second": int(n / elapsed) if elapsed > 0 else 0,
            "rows_verified": count,
        }
        results.append(result)
        print(
            f"  Database {n:>8,} events | "
            f"{elapsed:.4f}s | "
            f"{result['events_per_second']:>10,} ev/s | "
            f"{count} rows"
        )

    return results


if __name__ == "__main__":
    print("=== Database Benchmark ===")
    run_database_benchmark()
