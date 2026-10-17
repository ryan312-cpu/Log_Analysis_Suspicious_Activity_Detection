from pathlib import Path
from typing import List


class FileReader:

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)

    def exists(self) -> bool:
        return self.file_path.exists()

    def read_lines(self) -> List[str]:

        if not self.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.file_path}"
            )

        with open(
            self.file_path,
            "r",
            encoding="utf-8",
        ) as file:

            return [
                line.rstrip("\n")
                for line in file
            ]

    def count_lines(self) -> int:
        return len(self.read_lines())
