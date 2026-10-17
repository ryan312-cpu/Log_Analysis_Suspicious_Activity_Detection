import csv
from dataclasses import asdict
from pathlib import Path

from src.parsers.authentication_parser import AuthenticationParser
from src.parsers.web_parser import WebParser
from src.parsers.application_parser import ApplicationParser
from src.parsers.security_parser import SecurityParser
from src.parsers.system_parser import SystemParser

OUTPUT_FILE = Path("data/normalized/raw_parsed_events.csv")


def main():

    parsers = [
        AuthenticationParser(
            "data/raw/authentication/authentication.log"
        ),
        WebParser(
            "data/raw/web/web_access.log"
        ),
        ApplicationParser(
            "data/raw/application/application.log"
        ),
        SecurityParser(
            "data/raw/security/security.log"
        ),
        SystemParser(
            "data/raw/system/system.log"
        ),
    ]

    all_events = []

    for parser in parsers:

        events = parser.parse()

        print(
            f"{parser.__class__.__name__}: "
            f"{len(events)} events"
        )

        all_events.extend(events)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not all_events:
        print("No events were parsed.")
        return

    rows = [
        asdict(event)
        for event in all_events
    ]

    fieldnames = list(rows[0].keys())

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)

    print()
    print(
        f"Total parsed events: "
        f"{len(all_events)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
