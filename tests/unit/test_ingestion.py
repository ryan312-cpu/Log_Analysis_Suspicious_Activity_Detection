from src.ingestion.file_reader import FileReader
from src.ingestion.log_collector import LogCollector


def test_file_reader():

    reader = FileReader(
        "data/raw/authentication/authentication.log"
    )

    assert reader.exists()

    lines = reader.read_lines()

    assert len(lines) > 0


def test_log_collector():

    collector = LogCollector(
        "data/raw"
    )

    files = collector.discover_log_files()

    assert len(files) >= 5


def test_log_collection():

    collector = LogCollector(
        "data/raw"
    )

    collected = collector.collect()

    assert len(collected) >= 5
