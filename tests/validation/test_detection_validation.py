from src.detection.validation_metrics import (
    calculate_metrics,
)


def test_perfect_detection():

    metrics = calculate_metrics(
        true_positive=50,
        true_negative=50,
        false_positive=0,
        false_negative=0,
    )

    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0


def test_false_positive():

    metrics = calculate_metrics(
        true_positive=40,
        true_negative=40,
        false_positive=10,
        false_negative=0,
    )

    assert metrics.accuracy < 1.0
    assert metrics.precision < 1.0
    assert metrics.recall == 1.0


def test_false_negative():

    metrics = calculate_metrics(
        true_positive=40,
        true_negative=40,
        false_positive=0,
        false_negative=10,
    )

    assert metrics.accuracy < 1.0
    assert metrics.precision == 1.0
    assert metrics.recall < 1.0


def test_no_samples():

    metrics = calculate_metrics(
        true_positive=0,
        true_negative=0,
        false_positive=0,
        false_negative=0,
    )

    assert metrics.accuracy == 0.0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
