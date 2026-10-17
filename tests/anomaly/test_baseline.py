from src.anomaly.scoring import calculate_z_score


def test_z_score():

    result = calculate_z_score(
        value=10,
        mean_value=5,
        standard_deviation=1,
    )

    assert result == 5


def test_zero_standard_deviation():

    result = calculate_z_score(
        value=10,
        mean_value=5,
        standard_deviation=0,
    )

    assert result == 0
