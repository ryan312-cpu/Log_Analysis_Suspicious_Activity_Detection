VALID_STATUSES = {
    "NEW",
    "ACKNOWLEDGED",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
}


def validate_status(status: str) -> bool:

    return status.upper() in VALID_STATUSES


def allowed_transition(
    current: str,
    new: str,
) -> bool:

    transitions = {
        "NEW": {"ACKNOWLEDGED", "FALSE_POSITIVE"},
        "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED"},
        "INVESTIGATING": {"RESOLVED", "FALSE_POSITIVE"},
        "RESOLVED": set(),
        "FALSE_POSITIVE": set(),
    }

    return new.upper() in transitions.get(
        current.upper(),
        set(),
    )
