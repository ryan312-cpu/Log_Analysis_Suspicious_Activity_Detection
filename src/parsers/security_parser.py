import re
from typing import List

from src.normalization.schema import NormalizedEvent
from src.parsers.base_parser import BaseParser


class SecurityParser(BaseParser):

    def parse(self) -> List[NormalizedEvent]:

        events = []

        for index, line in enumerate(self.read_lines(), start=1):

            pattern = (
                r"^(?P<timestamp>\S+\s+\S+)\s+"
                r"FIREWALL\s+"
                r"action=(?P<action>\S+)\s+"
                r"src=(?P<source_ip>\S+)\s+"
                r"dst=(?P<destination_ip>\S+)\s+"
                r"service=(?P<service>\S+)$"
            )

            match = re.match(pattern, line)

            if not match:
                continue

            data = match.groupdict()

            events.append(
                NormalizedEvent(
                    event_id=f"SEC-{index:06d}",
                    timestamp=data["timestamp"],
                    event_type="FIREWALL_EVENT",
                    event_category="security",
                    source_ip=data["source_ip"],
                    destination_ip=data["destination_ip"],
                    service=data["service"],
                    action=data["action"],
                    status=data["action"],
                    source_type="firewall",
                    raw_log=line,
                )
            )

        return events
