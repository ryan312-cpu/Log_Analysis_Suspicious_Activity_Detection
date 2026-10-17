import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/normalized/events.csv")

NORMAL_OUTPUT = Path(
    "data/test/normal_events.csv"
)

SUSPICIOUS_OUTPUT = Path(
    "data/test/suspicious_events.csv"
)


def split_events(df: pd.DataFrame):
    normal = df[df["label"] == "normal"].copy()
    suspicious = df[df["label"] == "suspicious"].copy()
    return normal, suspicious


def main():
    print("Loading normalized dataset...")

    df = pd.read_csv(INPUT_FILE)

    normal, suspicious = split_events(df)

    NORMAL_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    normal.to_csv(
        NORMAL_OUTPUT,
        index=False,
    )

    suspicious.to_csv(
        SUSPICIOUS_OUTPUT,
        index=False,
    )

    print()
    print("Dataset split completed.")
    print(f"Normal events: {len(normal)}")
    print(f"Suspicious events: {len(suspicious)}")
    print()
    print(f"Normal dataset: {NORMAL_OUTPUT}")
    print(f"Suspicious dataset: {SUSPICIOUS_OUTPUT}")


if __name__ == "__main__":
    main()
