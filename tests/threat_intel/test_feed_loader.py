import pytest

from src.threat_intel.feed_loader import load_threat_feed


def test_feed_loads_controlled_documentation_ips():
    records = load_threat_feed()

    assert len(records) == 3
    assert records["203.0.113.50"].threat_type == "brute_force"
    assert records["203.0.113.50"].confidence == 90
    assert records["203.0.113.50"].source == "LAB-TI"


def test_feed_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="Threat intelligence feed"):
        load_threat_feed(tmp_path / "missing.csv")


@pytest.mark.parametrize(
    ("header", "row", "error"),
    [
        (
            "ip_address,threat_type,confidence,source,description",
            "not-an-ip,scan,80,test,description",
            "Invalid IP address",
        ),
        (
            "ip_address,threat_type,confidence,source,description",
            "203.0.113.1,scan,101,test,description",
            "between 0 and 100",
        ),
        (
            "ip_address,threat_type,confidence,source,description",
            "203.0.113.1,scan,high,test,description",
            "Invalid confidence",
        ),
    ],
)
def test_feed_rejects_invalid_records(tmp_path, header, row, error):
    feed = tmp_path / "feed.csv"
    feed.write_text(f"{header}\n{row}\n", encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        load_threat_feed(feed)


def test_feed_rejects_duplicate_canonical_ips(tmp_path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "ip_address,threat_type,confidence,source,description\n"
        "203.0.113.1,scan,80,test,first\n"
        "203.0.113.1,scan,90,test,second\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate IP"):
        load_threat_feed(feed)