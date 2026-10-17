import re
from typing import List

from src.normalization.schema import NormalizedEvent
from src.parsers.base_parser import BaseParser


class SystemParser(BaseParser):

    def parse(self) -> List[NormalizedEvent]:

        events = []

        for index, line in enumerate(self.read_lines(), start=1):

            match = re.match(
                r"^(?P<timestamp>\S+\s+\S+)\s+"
                r"SYSTEM\s+"
                r"service=(?P<service>\S+)\s+"
                r"status=(?P<status>\S+)$",
                line,
            )

            if not match:
                continue

            data = match.groupdict()

            events.append(
                NormalizedEvent(
                    event_id=f"SYS-{index:06d}",
                    timestamp=data["timestamp"],
                    event_type="SYSTEM_EVENT",
                    event_category="system",
                    service=data["service"],
                    status=data["status"],
                    source_type="system",
                    raw_log=line,
                )
            )

        return events
