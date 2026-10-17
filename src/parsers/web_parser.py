import re
from typing import List

from src.normalization.schema import NormalizedEvent
from src.parsers.base_parser import BaseParser


class WebParser(BaseParser):

    def parse(self) -> List[NormalizedEvent]:

        events = []

        for index, line in enumerate(self.read_lines(), start=1):

            pattern = (
                r"^(?P<timestamp>\S+\s+\S+)\s+"
                r"src=(?P<source_ip>\S+)\s+"
                r"method=(?P<method>\S+)\s+"
                r"path=(?P<path>\S+)\s+"
                r"status=(?P<status>\d+)$"
            )

            match = re.match(pattern, line)

            if not match:
                continue

            data = match.groupdict()

            response_code = int(data["status"])

            events.append(
                NormalizedEvent(
                    event_id=f"WEB-{index:06d}",
                    timestamp=data["timestamp"],
                    event_type="HTTP_REQUEST",
                    event_category="web",
                    source_ip=data["source_ip"],
                    service="http",
                    action="request",
                    status=(
                        "success"
                        if response_code < 400
                        else "error"
                    ),
                    http_method=data["method"],
                    http_path=data["path"],
                    response_code=response_code,
                    source_type="web",
                    raw_log=line,
                )
            )

        return events
