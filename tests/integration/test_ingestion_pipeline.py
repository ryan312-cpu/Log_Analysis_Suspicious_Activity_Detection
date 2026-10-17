import csv

from src.ingestion.pipeline import run_ingestion


def test_ingestion_pipeline_parses_validates_deduplicates_and_writes(tmp_path):
    source_directory = tmp_path / "raw"
    authentication_directory = source_directory / "authentication"
    authentication_directory.mkdir(parents=True)
    first_log = authentication_directory / "auth_a.log"
    second_log = authentication_directory / "auth_b.log"
    valid_line = (
        "2026-09-25 08:00:00 LOGIN_SUCCESS "
        "src=192.0.2.25 user=alice service=ssh"
    )
    first_log.write_text(
        f"{valid_line}\nmalformed record\n",
        encoding="utf-8",
    )
    second_log.write_text(f"{valid_line}\n", encoding="utf-8")
    output_file = tmp_path / "normalized" / "events.csv"

    summary = run_ingestion(source_directory, output_file)

    assert summary.files_discovered == 2
    assert summary.total_lines == 3
    assert summary.parsed_lines == 2
    assert summary.skipped_lines == 1
    assert summary.duplicates_removed == 1
    assert summary.unique_events == 1

    with output_file.open(newline="", encoding="utf-8") as output:
        rows = list(csv.DictReader(output))

    assert len(rows) == 1
    assert rows[0]["event_category"] == "authentication"
    assert rows[0]["raw_log"] == valid_line