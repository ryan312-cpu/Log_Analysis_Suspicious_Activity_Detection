def calculate_z_score(
    value: float,
    mean_value: float,
    standard_deviation: float,
) -> float:

    if standard_deviation == 0:
        return 0.0

    return (value - mean_value) / standard_deviation


def anomaly_score_from_z(
    z_score: float,
) -> float:

    magnitude = abs(z_score)

    if magnitude >= 4:
        return 100.0

    if magnitude >= 3:
        return 90.0

    if magnitude >= 2:
        return 75.0

    if magnitude >= 1:
        return 50.0

    return 20.0


def severity_from_anomaly_score(
    score: float,
) -> str:

    if score >= 90:
        return "CRITICAL"

    if score >= 75:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    return "LOW"
