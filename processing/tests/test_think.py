"""§4.7 retransmission dedupe, turn filters and session-level merging."""

import pytest

from extraction.config import Config
from extraction.features import compute_all

from .pcaps import ACK, PSH, Pkt, table

DATA = PSH | ACK

# V answers, A replies; A's reply is then retransmitted after a second V segment.
RETRANS = [
    Pkt(0.0, "A", 10, DATA, seq=100),
    Pkt(0.1, "V", 300, DATA, seq=900),
    Pkt(1.1, "A", 20, DATA, seq=110),
    Pkt(1.2, "V", 50, DATA, seq=1200),
    Pkt(2.2, "A", 20, DATA, seq=110),  # retransmission of the packet at 1.1
]


def test_retransmission_dropped():
    r = compute_all(table(RETRANS), Config())
    assert r.n_retrans_dropped == 1
    # Without the duplicate, V(0.1) A(1.1) V(1.2) -> one turn only.
    assert r.turns["think_time"].tolist() == pytest.approx([1.0])
    assert r.n_turns == 1


def test_dedupe_off_keeps_retransmission():
    r = compute_all(table(RETRANS), Config(dedupe_tcp_retransmissions=False))
    assert r.n_retrans_dropped == 0
    assert r.turns["think_time"].tolist() == pytest.approx([1.0, 1.0])
    assert r.turns["response_bytes"].tolist() == [300, 50]


def test_same_seq_different_length_is_not_a_retransmission():
    pkts = RETRANS[:-1] + [Pkt(2.2, "A", 25, DATA, seq=110)]
    assert compute_all(table(pkts), Config()).n_retrans_dropped == 0


def test_same_seq_other_direction_is_not_a_retransmission():
    pkts = [Pkt(0.0, "A", 10, DATA, seq=100), Pkt(0.1, "V", 10, DATA, seq=100)]
    assert compute_all(table(pkts), Config()).n_retrans_dropped == 0


def test_udp_is_never_deduped():
    pkts = [
        Pkt(0.0, "A", 10, proto=17, dport=53),
        Pkt(0.1, "V", 50, proto=17, dport=53),
        Pkt(0.5, "A", 10, proto=17, dport=53),
    ]
    r = compute_all(table(pkts), Config())
    assert r.n_retrans_dropped == 0
    assert r.turns["think_time"].tolist() == pytest.approx([0.4])


def test_icmp_ignored_for_think_time():
    pkts = [Pkt(0.0, "A", 10, DATA, seq=1), Pkt(0.1, "V", proto=1), Pkt(0.2, "A", 10, DATA, seq=11)]
    assert compute_all(table(pkts), Config()).n_turns == 0


def test_consecutive_v_packets_form_one_run():
    pkts = [
        Pkt(0.0, "A", 10, DATA, seq=1),
        Pkt(0.1, "V", 100, DATA, seq=500),
        Pkt(0.2, "V", 200, DATA, seq=600),
        Pkt(0.3, "A", 0, ACK, seq=11),  # pure ACK does not end the V-run
        Pkt(0.4, "V", 300, DATA, seq=800),
        Pkt(2.4, "A", 10, DATA, seq=11),
    ]
    r = compute_all(table(pkts), Config())
    assert r.turns["think_time"].tolist() == pytest.approx([2.0])
    assert r.turns["response_bytes"].tolist() == [600]


def test_turns_cross_connections():
    # Response on one connection, next request on another: still one session-level turn.
    pkts = [
        Pkt(0.0, "V", 100, DATA, seq=1, sport=40000, dport=21),
        Pkt(1.5, "A", 10, DATA, seq=1, sport=40001, dport=6200),
    ]
    assert compute_all(table(pkts), Config()).turns["think_time"].tolist() == pytest.approx([1.5])


def test_filters():
    pkts = [
        Pkt(0.0, "A", 10, DATA, seq=1),
        Pkt(0.1, "V", 5, DATA, seq=100),  # small response (echo)
        Pkt(0.2, "A", 10, DATA, seq=11),  # think 0.1
        Pkt(0.3, "V", 500, DATA, seq=105),
        Pkt(3.3, "A", 10, DATA, seq=21),  # think 3.0
        Pkt(3.4, "V", 400, DATA, seq=605),
        Pkt(3.405, "A", 10, DATA, seq=31),  # think 0.005 (automatic response)
    ]
    r = compute_all(table(pkts), Config(min_response_bytes=10, min_think_time_s=0.01))
    assert r.turns["kept"].tolist() == [False, True, False]
    assert r.n_turns == 1
    assert r.features["think_median"] == pytest.approx(3.0)
