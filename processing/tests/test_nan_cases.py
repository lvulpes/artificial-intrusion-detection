"""§4 undefined cases must come out as NaN, never as 0 or an exception."""

import math

import pytest

from extraction.columns import FEATURE_COLUMNS
from extraction.config import Config
from extraction.features import compute_all

from .pcaps import ACK, PSH, Pkt, table


def features(pkts):
    return compute_all(table(pkts), Config()).features


def nan(value) -> bool:
    return isinstance(value, float) and math.isnan(value)


def test_empty_table():
    f = features([])
    assert f["n_bursts_t1s"] == 0 and f["n_bursts_t5s"] == 0
    assert all(nan(v) for k, v in f.items() if not k.startswith("n_bursts"))


def test_single_packet():
    f = features([Pkt(1.0, "A")])
    assert f["duration_s"] == 0
    for name in ("pkt_rate_all", "byte_rate_a", "bursts_per_min_t1s", "duty_cycle_t1s",
                 "iat_all_mean", "iat_a_min", "burstiness", "idle_min_t1s", "pkt_ratio_a_v"):
        assert nan(f[name]), name
    assert f["n_bursts_t1s"] == 1
    assert f["pkts_per_burst_t1s"] == 1
    assert f["bytes_per_burst_t1s"] == 40


def test_zero_duration():
    f = features([Pkt(1.0, "A"), Pkt(1.0, "V")])
    assert f["duration_s"] == 0
    assert nan(f["pkt_rate_all"]) and nan(f["byte_rate_v"]) and nan(f["duty_cycle_t5s"])
    assert f["iat_all_mean"] == 0
    assert nan(f["burstiness"])  # sigma + mu = 0
    assert nan(f["iat_a_mean"])  # only one A packet


def test_no_victim_packets():
    f = features([Pkt(0.0, "A"), Pkt(1.0, "A")])
    assert nan(f["pkt_ratio_a_v"]) and nan(f["byte_ratio_a_v"])
    assert f["pkt_rate_v"] == 0


def test_victim_packets_without_bytes_cannot_happen_but_ratio_guards():
    # ip_len is never 0 for a real packet; check the guard is on the byte sum, not the count.
    t = table([Pkt(0.0, "A"), Pkt(1.0, "V")])
    t.loc[t["dir"] == "V", "ip_len"] = 0
    f = compute_all(t, Config()).features
    assert f["pkt_ratio_a_v"] == 1
    assert nan(f["byte_ratio_a_v"])


def test_single_burst_has_no_idle_gaps():
    f = features([Pkt(0.0, "A"), Pkt(0.5, "V"), Pkt(0.9, "A")])
    assert f["n_bursts_t1s"] == 1
    assert all(nan(f[f"idle_{s}_t1s"]) for s in ("min", "max", "mean", "median"))
    assert f["duty_cycle_t1s"] == pytest.approx(1.0)


def test_gap_equal_to_tau_does_not_split():
    f = features([Pkt(0.0, "A"), Pkt(1.0, "V"), Pkt(2.0, "A")])
    assert f["n_bursts_t1s"] == 1


def _turns(think_times, sizes):
    """Alternating V/A data packets producing one turn per (think, size) pair."""
    pkts, t, seq = [Pkt(0.0, "A", 10, PSH | ACK, seq=1)], 0.0, 100
    for think, size in zip(think_times, sizes):
        t += 0.1
        pkts.append(Pkt(t, "V", size, PSH | ACK, seq=seq))
        t += think
        seq += 1000
        pkts.append(Pkt(t, "A", 10, PSH | ACK, seq=seq))
    return pkts


def test_no_turns():
    f = features([Pkt(0.0, "A", 10, PSH | ACK), Pkt(0.1, "V", 0, ACK)])
    assert nan(f["think_median"]) and nan(f["think_cv"]) and nan(f["think_size_corr"])


def test_one_turn():
    f = features(_turns([2.0], [100]))
    assert f["think_median"] == pytest.approx(2.0)
    assert nan(f["think_cv"]) and nan(f["think_size_corr"])


def test_two_turns_no_correlation():
    f = features(_turns([1.0, 3.0], [100, 200]))
    assert f["think_cv"] == pytest.approx(0.5)
    assert nan(f["think_size_corr"])


def test_three_turns_correlation():
    f = features(_turns([1.0, 2.0, 3.0], [100, 300, 200]))
    assert f["think_size_corr"] == pytest.approx(0.5)


def test_constant_variable_correlation_is_nan():
    assert nan(features(_turns([1.0, 2.0, 3.0], [100, 100, 100]))["think_size_corr"])
    assert nan(features(_turns([2.0, 2.0, 2.0], [100, 200, 300]))["think_size_corr"])


def test_zero_mean_think_time_cv_is_nan():
    assert nan(features(_turns([0.0, 0.0], [100, 200]))["think_cv"])


def test_every_feature_present():
    assert list(features([]).keys()) == FEATURE_COLUMNS
