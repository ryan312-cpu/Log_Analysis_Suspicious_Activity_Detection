import pandas as pd
import pytest

from src.dataset.generator import FIELDNAMES, build_events
from src.dataset.splitter import split_events
from src.dataset.validator import (
    normalize_dataframe,
    validate_categories,
    validate_columns,
    validate_labels,
    validate_required_values,
    validate_timestamps,
)


def test_generated_events_match_schema_and_validate():
    events = build_events()
    dataframe = pd.DataFrame(events)

    assert list(dataframe.columns) == FIELDNAMES
    assert len(dataframe) == 62
    validate_columns(dataframe)
    validate_required_values(dataframe)
    validate_labels(dataframe)
    validate_categories(dataframe)
    validate_timestamps(dataframe)


def test_normalization_standardizes_fields():
    dataframe = pd.DataFrame(
        [
            {
                "timestamp": "2026-09-30 09:00:00",
                "source_ip": " 192.0.2.1 ",
                "username": None,
                "event_type": " login_success ",
                "event_category": " Authentication ",
                "label": " SUSPICIOUS ",
                "attack_category": None,
            }
        ]
    )

    normalized = normalize_dataframe(dataframe)

    assert normalized.loc[0, "source_ip"] == "192.0.2.1"
    assert normalized.loc[0, "username"] == ""
    assert normalized.loc[0, "event_type"] == "LOGIN_SUCCESS"
    assert normalized.loc[0, "event_category"] == "authentication"
    assert normalized.loc[0, "label"] == "suspicious"
    assert normalized.loc[0, "attack_category"] == ""


def test_required_columns_are_enforced():
    with pytest.raises(ValueError, match="Missing required columns"):
        validate_columns(pd.DataFrame({"timestamp": []}))


def test_invalid_labels_and_categories_are_rejected():
    with pytest.raises(ValueError, match="Invalid labels"):
        validate_labels(pd.DataFrame({"label": ["unknown"]}))

    with pytest.raises(ValueError, match="Invalid event categories"):
        validate_categories(pd.DataFrame({"event_category": ["other"]}))


def test_required_values_and_timestamps_are_enforced():
    dataframe = pd.DataFrame(
        {
            "timestamp": ["not-a-time"],
            "event_type": ["LOGIN_FAILED"],
            "event_category": ["authentication"],
            "label": ["normal"],
            "reason": ["example"],
        }
    )

    with pytest.raises(ValueError, match="invalid timestamps"):
        validate_timestamps(dataframe)

    dataframe.loc[0, "reason"] = " "
    with pytest.raises(ValueError, match="Missing required values"):
        validate_required_values(dataframe)


def test_split_is_exhaustive_and_keeps_classes_separate():
    dataframe = pd.DataFrame(build_events())
    normal, suspicious = split_events(dataframe)

    assert len(normal) == 13
    assert len(suspicious) == 49
    assert set(normal["label"]) == {"normal"}
    assert set(suspicious["label"]) == {"suspicious"}
    assert len(normal) + len(suspicious) == len(dataframe)