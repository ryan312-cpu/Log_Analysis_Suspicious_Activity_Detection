"""
Input validation and sanitization for API endpoints.

Rejects SQL metacharacters, path traversal, XSS tags, null bytes,
oversized payloads, invalid IPs, and invalid timestamps.
"""
import ipaddress
import re
from datetime import datetime
from typing import Optional

from fastapi import HTTPException, status

MAX_STRING_LENGTH = 500

DANGEROUS_PATTERNS = [
    (r"['\"\\;]", r"SQL injection characters"),
    (r"\.\.[\\/]", "Path traversal sequence"),
    (r"<[^>]*>", "HTML/script tags"),
    (r"%00", "Null byte injection"),
    (r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+", "SQL logical operator injection"),
]

COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in DANGEROUS_PATTERNS
]


def find_input_issue(value: str, field_name: str = "input") -> Optional[str]:
    """Return a human-readable issue, or None if the value is acceptable."""
    if "\x00" in value:
        return f"Invalid input in '{field_name}': Null byte injection detected"
    if len(value) > MAX_STRING_LENGTH:
        return f"Field '{field_name}' exceeds maximum length of {MAX_STRING_LENGTH}"
    for pattern, description in COMPILED_PATTERNS:
        if pattern.search(value):
            return f"Invalid input in '{field_name}': {description} detected"
    return None


def validate_string_input(value: str, field_name: str = "input") -> str:
    """
    Validate a string input for dangerous content.
    Raises HTTP 422 if malicious patterns are detected or length exceeded.
    """
    issue = find_input_issue(value, field_name)
    if issue:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=issue,
        )
    return value.strip()


def validate_optional_string(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    return validate_string_input(value, field_name)


def validate_ip_address(ip: str) -> str:
    """Validate an IP address (v4 or v6). Raises HTTP 422 for invalid addresses."""
    validate_string_input(ip, "ip_address")
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid IP address: '{ip}'",
        )


def validate_optional_ip(ip: Optional[str]) -> Optional[str]:
    if ip is None:
        return None
    return validate_ip_address(ip)


def validate_timestamp(ts: str) -> str:
    """Validate an ISO 8601 timestamp. Raises HTTP 422 for invalid values."""
    validate_string_input(ts, "timestamp")
    candidate = ts.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(candidate)
        return ts
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid timestamp format: '{ts}'. Expected ISO 8601.",
        )


def validate_optional_timestamp(ts: Optional[str]) -> Optional[str]:
    if ts is None:
        return None
    return validate_timestamp(ts)
