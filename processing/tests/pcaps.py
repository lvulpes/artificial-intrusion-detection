"""Test helpers: hand-built packets, link layers and pcap files, plus in-memory packet tables."""

import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import dpkt
import pandas as pd

from extraction.parse import DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, TABLE_COLUMNS, TABLE_DTYPES

ATTACKER = "10.10.10.20"
VICTIM = "10.10.10.10"
OTHER = "10.10.10.99"

SYN, ACK, PSH = 0x02, 0x10, 0x08


@dataclass
class Pkt:
    ts: float
    dir: str  # "A" or "V"
    payload_len: int = 0
    flags: int = ACK
    seq: int = 0
    proto: int = 6
    sport: int = 40000  # attacker-side port; swapped for V packets
    dport: int = 21
    tcp_opts: int = 0  # bytes of TCP options (multiple of 4)


def ipv4(src: str, dst: str, proto: int, l4: bytes, payload_len: int, frag: int = 0) -> bytes:
    total = 20 + len(l4) + payload_len
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, frag, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + l4 + b"\x00" * payload_len


def tcp(sport: int, dport: int, seq: int, flags: int, opts: int = 0) -> bytes:
    doff = (20 + opts) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, doff << 4, flags, 65535, 0, 0) + b"\x01" * opts


def udp(sport: int, dport: int, payload_len: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)


def icmp() -> bytes:
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1)


def ip_bytes(p: Pkt, attacker: str = ATTACKER, victim: str = VICTIM) -> bytes:
    src, dst = (attacker, victim) if p.dir == "A" else (victim, attacker)
    sport, dport = (p.sport, p.dport) if p.dir == "A" else (p.dport, p.sport)
    if p.proto == 6:
        return ipv4(src, dst, 6, tcp(sport, dport, p.seq, p.flags, p.tcp_opts), p.payload_len)
    if p.proto == 17:
        return ipv4(src, dst, 17, udp(sport, dport, p.payload_len), p.payload_len)
    return ipv4(src, dst, p.proto, icmp(), 0)


def ether(payload: bytes, ethertype: int = 0x0800, vlan: bool = False) -> bytes:
    head = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
    if vlan:
        head += struct.pack("!HH", 0x8100, 100)
    return head + struct.pack("!H", ethertype) + payload


def sll(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 6 + b"\x00\x00", ethertype) + payload


def sll2(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack("!HHIHBB8s", ethertype, 0, 2, 1, 0, 6, b"\x02" * 6 + b"\x00\x00") + payload


LINKS = {DLT_EN10MB: ether, DLT_LINUX_SLL: sll, DLT_LINUX_SLL2: sll2}


def write_pcap(path: Path, frames: list[tuple[float, bytes]], linktype: int = DLT_EN10MB,
               snaplen: int = 65535) -> Path:
    """Classic nanosecond pcap; frames longer than snaplen are truncated like tcpdump -s would."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, linktype))
        for ts, frame in frames:
            ns = round(ts * 1e9)
            captured = frame[:snaplen]
            f.write(struct.pack("<IIII", ns // 10**9, ns % 10**9, len(captured), len(frame)))
            f.write(captured)
    return path


def write_pcapng(path: Path, frames: list[tuple[float, bytes]], linktype: int = DLT_EN10MB) -> Path:
    with open(path, "wb") as f:
        writer = dpkt.pcapng.Writer(f, linktype=linktype)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)
    return path


def frames(pkts: list[Pkt], linktype: int = DLT_EN10MB, t0: float = 1_700_000_000.0) -> list[tuple[float, bytes]]:
    wrap = LINKS[linktype]
    return [(t0 + p.ts, wrap(ip_bytes(p))) for p in pkts]


def table(pkts: list[Pkt]) -> pd.DataFrame:
    """Per-packet table as parse_pcap would produce it, without going through a pcap."""
    rows = []
    for p in pkts:
        l4_len = {6: 20 + p.tcp_opts, 17: 8}.get(p.proto, 8)
        sport, dport = (p.sport, p.dport) if p.dir == "A" else (p.dport, p.sport)
        is_tcp = p.proto == 6
        rows.append({
            "ts": p.ts, "dir": p.dir, "ip_len": 20 + l4_len + p.payload_len,
            "payload_len": p.payload_len if p.proto in (6, 17) else 0, "proto": p.proto,
            "sport": sport if p.proto in (6, 17) else -1, "dport": dport if p.proto in (6, 17) else -1,
            "tcp_flags": p.flags if is_tcp else -1, "tcp_seq": p.seq if is_tcp else -1,
        })
    df = pd.DataFrame(rows, columns=TABLE_COLUMNS)
    return df.astype({**TABLE_DTYPES, "dir": object})


# §5 worked example. Sequence numbers advance per direction so nothing looks like a retransmission.
WORKED_EXAMPLE = [
    Pkt(0.000, "A", 0, SYN, seq=1000),
    Pkt(0.001, "V", 0, SYN | ACK, seq=5000),
    Pkt(0.002, "A", 0, ACK, seq=1001),
    Pkt(0.010, "A", 20, PSH | ACK, seq=1001),
    Pkt(0.050, "V", 500, PSH | ACK, seq=5001),
    Pkt(0.051, "A", 0, ACK, seq=1021),
    Pkt(3.051, "A", 30, PSH | ACK, seq=1021),
    Pkt(3.100, "V", 100, PSH | ACK, seq=5501),
    Pkt(3.150, "V", 200, PSH | ACK, seq=5601),
    Pkt(10.150, "A", 10, PSH | ACK, seq=1051),
    Pkt(10.200, "V", 0, ACK, seq=5801),
]
