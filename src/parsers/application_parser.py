import re
from typing import List

from src.normalization.schema import NormalizedEvent
from src.parsers.base_parser import BaseParser


class ApplicationParser(BaseParser):

    def parse(self) -> List[NormalizedEvent]:

        events = []

        for index, line in enumerate(self.read_lines(), start=1):

            match = re.match(
                r"^(?P<timestamp>\S+\s+\S+)\s+"
                r"(?P<event_type>\S+)\s+"
                r"(?P<fields>.*)$",
                line,
            )

            if not match:
                continue

            data = match.groupdict()

            fields = dict(
                re.findall(
                    r"(\w+)=(\S+)",
                    data["fields"],
                )
            )

            events.append(
                NormalizedEvent(
                    event_id=f"APP-{index:06d}",
                    timestamp=data["timestamp"],
                    event_type=data["event_type"],
                    event_category="application",
                    source_ip=fields.get("src"),
                    username=fields.get("user"),
                    service=fields.get("service"),
                    action=fields.get("action"),
                    status=fields.get("status")
                    or fields.get("error"),
                    source_type="application",
                    raw_log=line,
                )
            )

        return events
