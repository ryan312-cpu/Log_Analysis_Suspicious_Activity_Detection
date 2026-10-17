from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from src.normalization.schema import NormalizedEvent


class BaseParser(ABC):

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)

    def read_lines(self) -> List[str]:
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.file_path}"
            )

        with open(
            self.file_path,
            "r",
            encoding="utf-8",
        ) as file:
            return [
                line.strip()
                for line in file
                if line.strip()
            ]

    @abstractmethod
    def parse(self) -> List[NormalizedEvent]:
        pass
