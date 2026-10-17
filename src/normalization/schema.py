from dataclasses import dataclass
from typing import Optional


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str

    event_type: str
    event_category: str

    source_ip: Optional[str] = None
    source_port: Optional[int] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    username: Optional[str] = None
    hostname: Optional[str] = None
    service: Optional[str] = None

    action: Optional[str] = None
    status: Optional[str] = None

    http_method: Optional[str] = None
    http_path: Optional[str] = None
    response_code: Optional[int] = None

    user_agent: Optional[str] = None

    source_type: Optional[str] = None
    raw_log: Optional[str] = None
