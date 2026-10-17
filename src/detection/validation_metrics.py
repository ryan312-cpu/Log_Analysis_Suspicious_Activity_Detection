from dataclasses import dataclass


@dataclass
class ClassificationMetrics:
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int

    accuracy: float
    precision: float
    recall: float
    f1_score: float


def calculate_metrics(
    true_positive: int,
    true_negative: int,
    false_positive: int,
    false_negative: int,
) -> ClassificationMetrics:

    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (true_positive + true_negative) / total
        if total > 0
        else 0.0
    )

    precision_denominator = (
        true_positive + false_positive
    )

    precision = (
        true_positive / precision_denominator
        if precision_denominator > 0
        else 0.0
    )

    recall_denominator = (
        true_positive + false_negative
    )

    recall = (
        true_positive / recall_denominator
        if recall_denominator > 0
        else 0.0
    )

    f1_denominator = (
        precision + recall
    )

    f1_score = (
        2 * precision * recall
        / f1_denominator
        if f1_denominator > 0
        else 0.0
    )

    return ClassificationMetrics(
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
    )


def metrics_as_percentages(
    metrics: ClassificationMetrics,
) -> dict:

    return {
        "accuracy": round(
            metrics.accuracy * 100,
            2,
        ),
        "precision": round(
            metrics.precision * 100,
            2,
        ),
        "recall": round(
            metrics.recall * 100,
            2,
        ),
        "f1_score": round(
            metrics.f1_score * 100,
            2,
        ),
    }
