SEVERITY_BASE_SCORES = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 90,
}


def calculate_risk_score(
    severity: str,
    evidence_count: int = 1,
    correlation_bonus: float = 0,
) -> float:

    base_score = SEVERITY_BASE_SCORES.get(
        severity.upper(),
        25,
    )

    evidence_bonus = min(
        evidence_count * 2,
        10,
    )

    score = (
        base_score
        + evidence_bonus
        + correlation_bonus
    )

    return min(
        round(score, 2),
        100.0,
    )


def severity_from_score(
    score: float,
) -> str:

    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"
