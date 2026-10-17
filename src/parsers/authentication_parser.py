import re
from typing import List

from src.normalization.schema import NormalizedEvent
from src.parsers.base_parser import BaseParser


class AuthenticationParser(BaseParser):

    def parse(self) -> List[NormalizedEvent]:

        events = []

        for index, line in enumerate(self.read_lines(), start=1):

            pattern = (
                r"^(?P<timestamp>\S+\s+\S+)\s+"
                r"(?P<event_type>\S+)\s+"
                r"src=(?P<source_ip>\S+)\s+"
                r"user=(?P<username>\S+)\s+"
                r"service=(?P<service>\S+)$"
            )

            match = re.match(pattern, line)

            if not match:
                continue

            data = match.groupdict()

            events.append(
                NormalizedEvent(
                    event_id=f"AUTH-{index:06d}",
                    timestamp=data["timestamp"],
                    event_type=data["event_type"],
                    event_category="authentication",
                    source_ip=data["source_ip"],
                    username=data["username"],
                    service=data["service"],
                    status=(
                        "success"
                        if data["event_type"] == "LOGIN_SUCCESS"
                        else "failed"
                    ),
                    source_type="authentication",
                    raw_log=line,
                )
            )

        return events
