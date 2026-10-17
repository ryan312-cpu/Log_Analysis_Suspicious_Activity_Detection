from src.incidents.lifecycle import allowed_incident_transition


def test_investigation_transition():
    assert allowed_incident_transition("TRIAGING", "INVESTIGATING")


def test_containment_transition():
    assert allowed_incident_transition("INVESTIGATING", "CONTAINED")


def test_resolution_transition():
    assert allowed_incident_transition("CONTAINED", "RESOLVED")


def test_closed_transition():
    assert allowed_incident_transition("RESOLVED", "CLOSED")
