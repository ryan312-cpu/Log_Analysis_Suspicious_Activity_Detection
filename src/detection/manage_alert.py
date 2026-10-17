import sys

from src.storage.database import get_session
from src.storage.alert_repository import AlertRepository


def main():

    if len(sys.argv) != 3:
        print(
            "Usage: python -m src.detection.manage_alert <ALERT_ID> <STATUS>"
        )
        return

    alert_id = sys.argv[1]
    new_status = sys.argv[2]

    session = get_session()

    try:
        repository = AlertRepository(session)
        alert = repository.update_status(
            alert_id,
            new_status,
        )
        print(
            f"Alert {alert.alert_id} updated to {alert.status}"
        )
    finally:
        session.close()


if __name__ == "__main__":
    main()
