from pathlib import Path
from typing import Dict, List

from src.ingestion.file_reader import FileReader


class LogCollector:

    def __init__(self, source_directory: str):
        self.source_directory = Path(
            source_directory
        )

    def discover_log_files(self) -> List[Path]:

        if not self.source_directory.exists():
            raise FileNotFoundError(
                f"Directory not found: "
                f"{self.source_directory}"
            )

        return sorted(
            self.source_directory.rglob("*.log")
        )

    def collect(self) -> Dict[str, List[str]]:

        log_files = self.discover_log_files()

        collected = {}

        for log_file in log_files:

            reader = FileReader(
                str(log_file)
            )

            collected[str(log_file)] = (
                reader.read_lines()
            )

        return collected
