"""Ingestion pipeline – orchestrates log collection, parsing, deduplication,
and writing normalised events to a CSV output file.

The public entry-point ``run_ingestion`` now accepts optional *source_directory*
and *output_file* arguments so it can be called from tests with temporary
directories as well as from the CLI with the project defaults.
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from src.ingestion.log_collector import LogCollector
from src.normalization.schema import NormalizedEvent
from src.parsers.authentication_parser import AuthenticationParser

_DEFAULT_SOURCE = Path("data/raw")
_DEFAULT_OUTPUT = Path("data/normalized/events.csv")

# Fields written to the output CSV (must match NormalizedEvent attributes).
_CSV_FIELDS = [
    "event_id",
    "timestamp",
    "event_type",
    "event_category",
    "source_ip",
    "username",
    "service",
    "status",
    "source_type",
    "raw_log",
]


@dataclass
class IngestionSummary:
    files_discovered: int = 0
    total_lines: int = 0
    parsed_lines: int = 0
    skipped_lines: int = 0
    duplicates_removed: int = 0
    unique_events: int = 0


def _parse_file(file_path: Path) -> List[NormalizedEvent]:
    """Select and run the appropriate parser for *file_path*."""
    # Determine category from the parent directory name.
    category = file_path.parent.name.lower()

    if category == "authentication":
        parser = AuthenticationParser(str(file_path))
        return parser.parse()

    # Fall back to authentication parser for unknown categories (best-effort).
    try:
        parser = AuthenticationParser(str(file_path))
        return parser.parse()
    except Exception:
        return []


def run_ingestion(
    source_directory: Path | str | None = None,
    output_file: Path | str | None = None,
) -> IngestionSummary:
    """Parse all ``*.log`` files under *source_directory*, deduplicate by
    *raw_log* content, and write unique normalised events to *output_file*.

    Returns an :class:`IngestionSummary` with counts for each stage.
    """
    source_directory = Path(source_directory) if source_directory else _DEFAULT_SOURCE
    output_file = Path(output_file) if output_file else _DEFAULT_OUTPUT

    summary = IngestionSummary()

    collector = LogCollector(str(source_directory))
    files = collector.discover_log_files()
    summary.files_discovered = len(files)

    print("=" * 60)
    print("LOG INGESTION PIPELINE")
    print("=" * 60)
    print(f"Discovered log files: {len(files)}")
    print()

    all_events: List[NormalizedEvent] = []

    for file_path in files:
        # Count raw lines for statistics.
        try:
            raw_lines = file_path.read_text(encoding="utf-8").splitlines()
            non_empty = [ln for ln in raw_lines if ln.strip()]
        except Exception:
            non_empty = []

        summary.total_lines += len(non_empty)

        parsed = _parse_file(file_path)
        summary.parsed_lines += len(parsed)
        summary.skipped_lines += len(non_empty) - len(parsed)
        all_events.extend(parsed)

        print(f"[INGESTED] {file_path} ({len(parsed)} events parsed)")

    # Deduplicate by raw log content.
    seen_raw: set[str] = set()
    unique_events: List[NormalizedEvent] = []
    for event in all_events:
        if event.raw_log in seen_raw:
            summary.duplicates_removed += 1
        else:
            seen_raw.add(event.raw_log)
            unique_events.append(event)

    summary.unique_events = len(unique_events)

    # Write output CSV.
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for event in unique_events:
            writer.writerow(
                {f: getattr(event, f, None) for f in _CSV_FIELDS}
            )

    print()
    print("-" * 60)
    print(f"Total lines read    : {summary.total_lines}")
    print(f"Lines parsed        : {summary.parsed_lines}")
    print(f"Lines skipped       : {summary.skipped_lines}")
    print(f"Duplicates removed  : {summary.duplicates_removed}")
    print(f"Unique events stored: {summary.unique_events}")
    print("-" * 60)

    return summary


if __name__ == "__main__":
    run_ingestion()
