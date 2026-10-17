from dataclasses import dataclass


@dataclass
class ParserStats:
    total_lines: int = 0
    parsed_lines: int = 0
    skipped_lines: int = 0

    @property
    def parse_success_rate(self) -> float:

        if self.total_lines == 0:
            return 0.0

        return (
            self.parsed_lines
            / self.total_lines
        ) * 100
