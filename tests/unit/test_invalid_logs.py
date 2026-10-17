from src.parsers.authentication_parser import AuthenticationParser


def test_invalid_authentication_lines_are_skipped(
    tmp_path,
):

    log_file = tmp_path / "invalid_auth.log"

    log_file.write_text(
        "\n".join(
            [
                "INVALID LOG ENTRY",
                "2026-09-25 08:00:00 "
                "LOGIN_SUCCESS "
                "src=192.168.10.25 "
                "user=alice "
                "service=ssh",
            ]
        ),
        encoding="utf-8",
    )

    parser = AuthenticationParser(
        str(log_file)
    )

    events = parser.parse()

    assert len(events) == 1
    assert events[0].username == "alice"
