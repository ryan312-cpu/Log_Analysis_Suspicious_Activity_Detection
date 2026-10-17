from src.parsers.authentication_parser import AuthenticationParser
from src.parsers.web_parser import WebParser
from src.parsers.application_parser import ApplicationParser
from src.parsers.security_parser import SecurityParser
from src.parsers.system_parser import SystemParser


def test_authentication_parser():
    parser = AuthenticationParser(
        "data/raw/authentication/authentication.log"
    )

    events = parser.parse()

    assert len(events) > 0
    assert events[0].event_category == "authentication"
    assert events[0].source_type == "authentication"


def test_web_parser():
    parser = WebParser(
        "data/raw/web/web_access.log"
    )

    events = parser.parse()

    assert len(events) > 0
    assert events[0].event_category == "web"
    assert events[0].http_method is not None


def test_application_parser():
    parser = ApplicationParser(
        "data/raw/application/application.log"
    )

    events = parser.parse()

    assert len(events) > 0
    assert events[0].event_category == "application"


def test_security_parser():
    parser = SecurityParser(
        "data/raw/security/security.log"
    )

    events = parser.parse()

    assert len(events) > 0
    assert events[0].event_category == "security"


def test_system_parser():
    parser = SystemParser(
        "data/raw/system/system.log"
    )

    events = parser.parse()

    assert len(events) > 0
    assert events[0].event_category == "system"


def test_authentication_event_fields():
    parser = AuthenticationParser(
        "data/raw/authentication/authentication.log"
    )

    events = parser.parse()

    event = events[0]

    assert event.event_id
    assert event.timestamp
    assert event.event_type
    assert event.source_ip
    assert event.username
    assert event.service


def test_web_response_code():
    parser = WebParser(
        "data/raw/web/web_access.log"
    )

    events = parser.parse()

    assert isinstance(
        events[0].response_code,
        int,
    )
