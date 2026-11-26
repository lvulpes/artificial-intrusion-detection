"""§5 worked example, through the feature functions."""

import math

import pytest

from extraction.columns import FEATURE_COLUMNS, FEATURE_GROUPS
from extraction.config import Config
from extraction.features import compute_all

from .pcaps import WORKED_EXAMPLE, table


@pytest.fixture
def result():
    return compute_all(table(WORKED_EXAMPLE), Config())


def test_column_list():
    assert len(FEATURE_COLUMNS) == 41
    assert list(FEATURE_GROUPS) == [
        "rates", "ratios", "duration", "iat", "burstiness", "bursts_t1s", "bursts_t5s", "think",
    ]
    assert FEATURE_GROUPS["bursts_t1s"][0] == "n_bursts_t1s"


def test_feature_order(result):
    assert list(result.features) == FEATURE_COLUMNS


def test_duration_and_rates(result):
    f = result.features
    assert f["duration_s"] == pytest.approx(10.2)
    assert f["pkt_rate_all"] == pytest.approx(11 / 10.2)
    assert f["pkt_rate_a"] == pytest.approx(6 / 10.2)
    assert f["pkt_ratio_a_v"] == pytest.approx(6 / 5)


def test_bursts_t1s(result):
    f = result.features
    assert f["n_bursts_t1s"] == 3
    assert f["pkts_per_burst_t1s"] == pytest.approx(11 / 3)
    assert f["idle_min_t1s"] == pytest.approx(3.0)
    assert f["idle_max_t1s"] == pytest.approx(7.0)
    assert f["idle_mean_t1s"] == pytest.approx(5.0)
    assert f["idle_median_t1s"] == pytest.approx(5.0)
    assert f["duty_cycle_t1s"] == pytest.approx(0.2 / 10.2)
    assert f["bursts_per_min_t1s"] == pytest.approx(17.647, abs=1e-3)


def test_bursts_t5s(result):
    f = result.features
    assert f["n_bursts_t5s"] == 2
    assert f["duty_cycle_t5s"] == pytest.approx(3.2 / 10.2)
    for stat in ("min", "max", "mean", "median"):
        assert f[f"idle_{stat}_t5s"] == pytest.approx(7.0)


def test_think_time(result):
    turns = result.turns
    assert turns["think_time"].tolist() == pytest.approx([3.001, 7.0])
    assert turns["response_bytes"].tolist() == [500, 300]
    f = result.features
    assert f["think_median"] == pytest.approx(5.0005)
    assert f["think_cv"] == pytest.approx(1.9995 / 5.0005)
    assert f["think_cv"] == pytest.approx(0.399860, abs=1e-6)
    assert math.isnan(f["think_size_corr"])
    assert result.n_turns == 2
    assert result.n_retrans_dropped == 0
