VALID_INCIDENT_STATUSES = {
    "OPEN",
    "TRIAGING",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
}

VALID_INCIDENT_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

TRANSITIONS = {
    "OPEN": {"TRIAGING", "CLOSED"},
    "TRIAGING": {"INVESTIGATING", "CLOSED"},
    "INVESTIGATING": {"CONTAINED", "RESOLVED", "CLOSED"},
    "CONTAINED": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set(),
}


def validate_incident_status(status: str) -> bool:
    return status.upper() in VALID_INCIDENT_STATUSES


def validate_incident_severity(severity: str) -> bool:
    return severity.upper() in VALID_INCIDENT_SEVERITIES


def allowed_incident_transition(current: str, new: str) -> bool:
    return new.upper() in TRANSITIONS.get(current.upper(), set())
