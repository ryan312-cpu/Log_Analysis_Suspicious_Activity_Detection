import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/labelled/labelled_events.csv")
OUTPUT_FILE = Path("data/normalized/events.csv")

REQUIRED_COLUMNS = [
    "timestamp",
    "event_type",
    "event_category",
    "source_ip",
    "username",
    "service",
    "status",
    "http_method",
    "http_path",
    "response_code",
    "label",
    "attack_category",
    "reason",
]


def validate_columns(df):
    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )


def validate_labels(df):
    valid_labels = {"normal", "suspicious"}

    invalid_labels = set(df["label"].dropna()) - valid_labels

    if invalid_labels:
        raise ValueError(
            f"Invalid labels found: {invalid_labels}"
        )


def validate_categories(df):
    valid_categories = {
        "authentication",
        "web",
        "firewall",
        "application",
        "system",
        "security",
    }
    if "event_category" in df.columns:
        invalid = set(df["event_category"].dropna().astype(str).str.lower().str.strip()) - valid_categories
        if invalid:
            raise ValueError(f"Invalid event categories: {invalid}")


def validate_required_values(df):
    required = ["timestamp", "event_type", "event_category", "label", "reason"]
    for col in required:
        if col in df.columns:
            empty_mask = df[col].isna() | df[col].astype(str).str.strip().eq("")
            if empty_mask.any():
                raise ValueError(f"Missing required values in column '{col}'")


def validate_timestamps(df):
    timestamps = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    invalid_count = timestamps.isna().sum()

    if invalid_count > 0:
        raise ValueError(
            f"{invalid_count} invalid timestamps found"
        )


def normalize_dataframe(df):
    df = df.copy()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    df["source_ip"] = (
        df["source_ip"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df["username"] = (
        df["username"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df["event_type"] = (
        df["event_type"]
        .fillna("")
        .astype(str)
        .str.upper()
        .str.strip()
    )

    df["event_category"] = (
        df["event_category"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
    )

    df["label"] = (
        df["label"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
    )

    if "attack_category" in df.columns:
        df["attack_category"] = (
            df["attack_category"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    return df


def main():
    print("Loading dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Loaded {len(df)} events")

    print("Validating columns...")
    validate_columns(df)

    print("Validating labels...")
    validate_labels(df)

    print("Validating timestamps...")
    validate_timestamps(df)

    print("Normalizing dataset...")
    df = normalize_dataframe(df)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print()
    print("Dataset validation successful.")
    print(f"Normalized dataset saved to: {OUTPUT_FILE}")
    print(f"Total events: {len(df)}")
    print()
    print("Label distribution:")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
