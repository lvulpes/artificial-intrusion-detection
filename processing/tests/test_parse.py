"""§2.1/§3: link types, truncated captures, filtering and attacker/victim inference."""

import pandas as pd
import pytest

from extraction.columns import FEATURE_COLUMNS
from extraction.config import Config
from extraction.features import compute_all
from extraction.parse import DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_RAW, parse_pcap

from . import pcaps
from .pcaps import ATTACKER, OTHER, SYN, VICTIM, WORKED_EXAMPLE, Pkt

T0 = 1_700_000_000.0


def assert_same_features(f1: dict, f2: dict, rel: float = 1e-12, abs_: float = 1e-9) -> None:
    for name in FEATURE_COLUMNS:
        a, b = f1[name], f2[name]
        assert (pd.isna(a) and pd.isna(b)) or a == pytest.approx(b, rel=rel, abs=abs_), name


def test_worked_example_from_pcap(tmp_path):
    path = pcaps.write_pcap(tmp_path / "x.pcap", pcaps.frames(WORKED_EXAMPLE))
    parsed = parse_pcap(path, ATTACKER, VICTIM)
    assert len(parsed.table) == 11
    assert parsed.table["dir"].tolist() == [p.dir for p in WORKED_EXAMPLE]
    assert parsed.table["payload_len"].tolist() == [p.payload_len for p in WORKED_EXAMPLE]
    assert parsed.table["ts"].iloc[0] == pytest.approx(T0)
    expected = compute_all(pcaps.table(WORKED_EXAMPLE), Config()).features
    # Epoch timestamps (~1.7e9 s) carry ~0.2 us resolution as float64, so only approximately equal.
    assert_same_features(compute_all(parsed.table, Config()).features, expected, rel=1e-6, abs_=1e-6)


def test_truncated_capture_matches_full(tmp_path):
    # Larger payloads and TCP options, so snaplen 96 cuts into headers' neighbourhood and payload.
    pkts = [Pkt(p.ts, p.dir, p.payload_len * 3, p.flags, p.seq, tcp_opts=12) for p in WORKED_EXAMPLE]
    pkts.append(Pkt(11.0, "A", 900, proto=17, dport=53))
    pkts.append(Pkt(11.5, "V", proto=1))
    frames = pcaps.frames(pkts)
    full = parse_pcap(pcaps.write_pcap(tmp_path / "full.pcap", frames), ATTACKER, VICTIM)
    cut = parse_pcap(pcaps.write_pcap(tmp_path / "cut.pcap", frames, snaplen=96), ATTACKER, VICTIM)
    pd.testing.assert_frame_equal(full.table, cut.table)
    assert cut.table["ip_len"].tolist() == [20 + 32 + p.payload_len for p in pkts[:-2]] + [20 + 8 + 900, 28]
    assert cut.table["payload_len"].tolist()[-2:] == [900, 0]
    assert_same_features(compute_all(full.table, Config()).features, compute_all(cut.table, Config()).features)
    assert not cut.warnings


@pytest.mark.parametrize("linktype", [DLT_LINUX_SLL, DLT_LINUX_SLL2])
def test_cooked_capture_matches_ethernet(tmp_path, linktype):
    eth = parse_pcap(pcaps.write_pcap(tmp_path / "eth.pcap", pcaps.frames(WORKED_EXAMPLE)), ATTACKER, VICTIM)
    path = pcaps.write_pcap(tmp_path / "sll.pcap", pcaps.frames(WORKED_EXAMPLE, linktype), linktype)
    cooked = parse_pcap(path, ATTACKER, VICTIM)
    pd.testing.assert_frame_equal(eth.table, cooked.table)


def test_raw_ip_and_vlan(tmp_path):
    raw = [(T0 + p.ts, pcaps.ip_bytes(p)) for p in WORKED_EXAMPLE]
    vlan = [(T0 + p.ts, pcaps.ether(pcaps.ip_bytes(p), vlan=True)) for p in WORKED_EXAMPLE]
    t_raw = parse_pcap(pcaps.write_pcap(tmp_path / "raw.pcap", raw, DLT_RAW), ATTACKER, VICTIM).table
    t_vlan = parse_pcap(pcaps.write_pcap(tmp_path / "vlan.pcap", vlan), ATTACKER, VICTIM).table
    assert len(t_raw) == len(t_vlan) == 11
    pd.testing.assert_frame_equal(t_raw, t_vlan)


def test_pcapng(tmp_path):
    eth = parse_pcap(pcaps.write_pcap(tmp_path / "a.pcap", pcaps.frames(WORKED_EXAMPLE)), ATTACKER, VICTIM)
    ng = parse_pcap(pcaps.write_pcapng(tmp_path / "a.pcapng", pcaps.frames(WORKED_EXAMPLE)), ATTACKER, VICTIM)
    pd.testing.assert_frame_equal(eth.table, ng.table, check_exact=False, atol=1e-6)


def test_unsupported_linktype(tmp_path):
    path = pcaps.write_pcap(tmp_path / "x.pcap", pcaps.frames(WORKED_EXAMPLE), linktype=105)
    with pytest.raises(ValueError, match="unsupported link type 105"):
        parse_pcap(path, ATTACKER, VICTIM)


def test_filters_other_hosts_arp_and_ipv6(tmp_path):
    frames = pcaps.frames(WORKED_EXAMPLE)
    noise = [
        (T0 + 0.3, pcaps.ether(b"\x00" * 28, ethertype=0x0806)),  # ARP
        (T0 + 0.4, pcaps.ether(b"\x60" + b"\x00" * 39, ethertype=0x86DD)),  # IPv6
        (T0 + 0.5, pcaps.ether(pcaps.ipv4(OTHER, VICTIM, 6, pcaps.tcp(1, 2, 0, SYN), 0))),
        (T0 + 0.6, pcaps.ether(pcaps.ipv4(ATTACKER, OTHER, 17, pcaps.udp(1, 2, 4), 4))),
    ]
    parsed = parse_pcap(pcaps.write_pcap(tmp_path / "x.pcap", sorted(frames + noise)), ATTACKER, VICTIM)
    assert parsed.n_packets_raw == 15
    assert len(parsed.table) == 11
    assert not parsed.ip_inferred


def test_unsorted_capture_is_sorted(tmp_path):
    frames = pcaps.frames(WORKED_EXAMPLE)
    frames[3], frames[4] = frames[4], frames[3]
    t = parse_pcap(pcaps.write_pcap(tmp_path / "x.pcap", frames), ATTACKER, VICTIM).table
    assert t["ts"].is_monotonic_increasing


def test_infer_from_first_syn(tmp_path):
    # Noise before the handshake, including a SYN-ACK from another host, must not fool it.
    noise = [
        (T0 - 1.0, pcaps.ether(pcaps.ipv4(OTHER, VICTIM, 17, pcaps.udp(1, 2, 0), 0))),
        (T0 - 0.5, pcaps.ether(pcaps.ipv4(OTHER, VICTIM, 6, pcaps.tcp(1, 2, 0, SYN | 0x10), 0))),
    ]
    path = pcaps.write_pcap(tmp_path / "x.pcap", noise + pcaps.frames(WORKED_EXAMPLE))
    parsed = parse_pcap(path)
    assert (parsed.attacker_ip, parsed.victim_ip) == (ATTACKER, VICTIM)
    assert parsed.ip_inferred
    assert len(parsed.table) == 11
    assert any("inferred" in w for w in parsed.warnings)
    assert not any("no TCP SYN" in w for w in parsed.warnings)


def test_infer_only_missing_victim(tmp_path):
    syn_from_other = (T0 - 1.0, pcaps.ether(pcaps.ipv4(OTHER, ATTACKER, 6, pcaps.tcp(1, 2, 0, SYN), 0)))
    path = pcaps.write_pcap(tmp_path / "x.pcap", [syn_from_other] + pcaps.frames(WORKED_EXAMPLE))
    parsed = parse_pcap(path, attacker_ip=ATTACKER)
    assert parsed.victim_ip == VICTIM


def test_infer_without_syn_falls_back_to_first_ipv4(tmp_path):
    pkts = [p for p in WORKED_EXAMPLE if not p.flags & SYN]
    parsed = parse_pcap(pcaps.write_pcap(tmp_path / "x.pcap", pcaps.frames(pkts)))
    assert (parsed.attacker_ip, parsed.victim_ip) == (ATTACKER, VICTIM)
    assert any("no TCP SYN" in w for w in parsed.warnings)


def test_corrupt_tail_keeps_earlier_packets(tmp_path):
    path = pcaps.write_pcap(tmp_path / "x.pcap", pcaps.frames(WORKED_EXAMPLE))
    with open(path, "ab") as f:
        f.write(b"\x01\x02\x03")  # partial record header, as when tcpdump is killed mid-write
    parsed = parse_pcap(path, ATTACKER, VICTIM)
    assert len(parsed.table) == 11
    assert any("truncated or corrupt" in w for w in parsed.warnings)


def test_no_matching_packets(tmp_path):
    parsed = parse_pcap(pcaps.write_pcap(tmp_path / "x.pcap", pcaps.frames(WORKED_EXAMPLE)), OTHER, VICTIM)
    assert parsed.table.empty
    assert any("no packets" in w for w in parsed.warnings)
