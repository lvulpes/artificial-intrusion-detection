"""pcap/pcapng -> per-packet table of attacker<->victim IPv4 packets (§3).

Headers are decoded by hand from fixed offsets so that truncated captures (small snaplen) behave
exactly like full ones: every size comes from the IPv4 Total Length and L4 header fields, never
from the captured length.
"""

import socket
import struct
from array import array
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_LINUX_SLL2 = 276
SUPPORTED_LINKTYPES = {DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_IPV4, DLT_LINUX_SLL2}

ETH_P_IP = 0x0800
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PROTO_TCP = 6
PROTO_UDP = 17
TCP_SYN = 0x02
TCP_ACK = 0x10

# Column -> dtype of the per-packet table. -1 marks "not applicable / not captured".
TABLE_DTYPES = {
    "ts": "float64",
    "ip_len": "int32",
    "payload_len": "int32",
    "proto": "int16",
    "sport": "int32",
    "dport": "int32",
    "tcp_flags": "int16",
    "tcp_seq": "int64",
}
TABLE_COLUMNS = ["ts", "dir", "ip_len", "payload_len", "proto", "sport", "dport", "tcp_flags", "tcp_seq"]


@dataclass
class ParseResult:
    table: pd.DataFrame
    n_packets_raw: int
    attacker_ip: str
    victim_ip: str
    ip_inferred: bool
    warnings: list[str] = field(default_factory=list)


@dataclass
class _Ipv4:
    src: bytes
    dst: bytes
    ip_len: int
    payload_len: int
    proto: int
    sport: int
    dport: int
    tcp_flags: int
    tcp_seq: int
    l4_truncated: bool
    bad_total_len: bool


def _ipv4_offset(linktype: int, buf: bytes) -> int | None:
    """Offset of the IPv4 header in a frame, or None if the frame is not IPv4."""
    if linktype == DLT_EN10MB:
        if len(buf) < 14:
            return None
        ethertype = int.from_bytes(buf[12:14], "big")
        offset = 14
        while ethertype in VLAN_ETHERTYPES and len(buf) >= offset + 4:
            ethertype = int.from_bytes(buf[offset + 2 : offset + 4], "big")
            offset += 4
        return offset if ethertype == ETH_P_IP else None
    if linktype == DLT_LINUX_SLL:
        if len(buf) < 16 or int.from_bytes(buf[14:16], "big") != ETH_P_IP:
            return None
        return 16
    if linktype == DLT_LINUX_SLL2:
        if len(buf) < 20 or int.from_bytes(buf[0:2], "big") != ETH_P_IP:
            return None
        return 20
    # DLT_RAW / DLT_IPV4: the frame starts with the IP header.
    return 0 if buf and buf[0] >> 4 == 4 else None


def _decode_ipv4(buf: bytes, offset: int) -> _Ipv4 | None:
    if len(buf) < offset + 20 or buf[offset] >> 4 != 4:
        return None
    ihl = (buf[offset] & 0x0F) * 4
    if ihl < 20:
        return None
    ip_len, frag = struct.unpack_from("!H2xH", buf, offset + 2)
    proto = buf[offset + 9]
    src = buf[offset + 12 : offset + 16]
    dst = buf[offset + 16 : offset + 20]

    sport = dport = tcp_flags = tcp_seq = -1
    l4_truncated = False
    bad_total_len = ip_len < ihl
    l4 = offset + ihl
    if frag & 0x1FFF:
        # Non-first fragment: no L4 header, the whole IP payload is upper-layer data.
        payload_len = ip_len - ihl
    elif proto == PROTO_TCP:
        if len(buf) >= l4 + 14:
            sport, dport, tcp_seq = struct.unpack_from("!HHI", buf, l4)
            tcp_flags = buf[l4 + 13]
            payload_len = ip_len - ihl - (buf[l4 + 12] >> 4) * 4
        else:
            # Data offset not captured: payload size unknown, treat as no payload.
            if len(buf) >= l4 + 4:
                sport, dport = struct.unpack_from("!HH", buf, l4)
            payload_len = 0
            l4_truncated = True
    elif proto == PROTO_UDP:
        if len(buf) >= l4 + 4:
            sport, dport = struct.unpack_from("!HH", buf, l4)
        payload_len = ip_len - ihl - 8
    else:
        payload_len = 0
    return _Ipv4(
        src, dst, ip_len, max(payload_len, 0), proto, sport, dport, tcp_flags, tcp_seq,
        l4_truncated, bad_total_len,
    )


def _open_reader(f) -> dpkt.pcap.Reader | dpkt.pcapng.Reader:
    magic = f.read(4)
    f.seek(0)
    if magic == PCAPNG_MAGIC:
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


def _iter_frames(path: Path, warnings: list[str]) -> Iterator[tuple[float, bytes, int]]:
    """Yield (ts, frame, linktype). Stops with a warning if the file is cut off mid-record."""
    with open(path, "rb") as f:
        reader = _open_reader(f)
        linktype = reader.datalink()
        if linktype not in SUPPORTED_LINKTYPES:
            raise ValueError(f"unsupported link type {linktype}")
        frames = iter(reader)
        n = 0
        while True:
            try:
                ts, buf = next(frames)
            except StopIteration:
                return
            except (dpkt.NeedData, dpkt.UnpackError, struct.error) as exc:
                warnings.append(f"capture truncated or corrupt after {n} packets ({type(exc).__name__})")
                return
            n += 1
            yield float(ts), buf, linktype


def _iter_ipv4(path: Path, warnings: list[str]) -> Iterator[tuple[float, _Ipv4 | None]]:
    """Yield (ts, decoded IPv4 or None) for every frame in the file."""
    for ts, buf, linktype in _iter_frames(path, warnings):
        offset = _ipv4_offset(linktype, buf)
        yield ts, None if offset is None else _decode_ipv4(buf, offset)


def _pack_ip(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _infer_endpoints(
    path: Path, attacker: str | None, victim: str | None, warnings: list[str]
) -> tuple[str, str]:
    """§3.1: attacker = source of the first SYN (no ACK), victim = its destination.

    A manifest value that is present constrains the search, so only the missing one is inferred.
    Falls back to the first IPv4 packet when the capture has no SYN.
    """
    want_src = _pack_ip(attacker) if attacker else None
    want_dst = _pack_ip(victim) if victim else None
    first_ipv4: _Ipv4 | None = None
    for _, pkt in _iter_ipv4(path, []):
        if pkt is None:
            continue
        if (want_src and pkt.src != want_src) or (want_dst and pkt.dst != want_dst):
            continue
        if first_ipv4 is None:
            first_ipv4 = pkt
        if pkt.proto == PROTO_TCP and pkt.tcp_flags >= 0 and pkt.tcp_flags & TCP_SYN and not pkt.tcp_flags & TCP_ACK:
            return socket.inet_ntoa(pkt.src), socket.inet_ntoa(pkt.dst)
    if first_ipv4 is None:
        raise ValueError("no IPv4 packet to infer attacker/victim from")
    warnings.append("no TCP SYN found; attacker inferred as source of the first IPv4 packet")
    return socket.inet_ntoa(first_ipv4.src), socket.inet_ntoa(first_ipv4.dst)


def parse_pcap(path: Path | str, attacker_ip: str | None = None, victim_ip: str | None = None) -> ParseResult:
    """Read a pcap/pcapng and return the filtered, time-sorted per-packet table (§3.2)."""
    path = Path(path)
    warnings: list[str] = []
    ip_inferred = not (attacker_ip and victim_ip)
    if ip_inferred:
        attacker_ip, victim_ip = _infer_endpoints(path, attacker_ip, victim_ip, warnings)
        warnings.append(f"attacker/victim inferred from capture: {attacker_ip} -> {victim_ip}")
    assert attacker_ip and victim_ip
    if attacker_ip == victim_ip:
        raise ValueError(f"attacker and victim are the same address {attacker_ip}")
    a, v = _pack_ip(attacker_ip), _pack_ip(victim_ip)

    cols = {
        "ts": array("d"), "is_a": array("b"), "ip_len": array("i"), "payload_len": array("i"),
        "proto": array("h"), "sport": array("i"), "dport": array("i"), "tcp_flags": array("h"),
        "tcp_seq": array("q"),
    }
    issues: Counter[str] = Counter()
    n_raw = 0
    for ts, pkt in _iter_ipv4(path, warnings):
        n_raw += 1
        if pkt is None:
            continue
        if pkt.src == a and pkt.dst == v:
            is_a = 1
        elif pkt.src == v and pkt.dst == a:
            is_a = 0
        else:
            continue
        issues["TCP header truncated, payload_len set to 0"] += pkt.l4_truncated
        issues["IPv4 total length < header length"] += pkt.bad_total_len
        cols["ts"].append(ts)
        cols["is_a"].append(is_a)
        cols["ip_len"].append(pkt.ip_len)
        cols["payload_len"].append(pkt.payload_len)
        cols["proto"].append(pkt.proto)
        cols["sport"].append(pkt.sport)
        cols["dport"].append(pkt.dport)
        cols["tcp_flags"].append(pkt.tcp_flags)
        cols["tcp_seq"].append(pkt.tcp_seq)
    warnings.extend(f"{msg}: {count} packets" for msg, count in issues.items() if count)

    data = {name: np.frombuffer(col, dtype=col.typecode) if len(col) else np.empty(0, col.typecode)
            for name, col in cols.items()}
    table = pd.DataFrame({
        "ts": data["ts"],
        "dir": np.where(data["is_a"] == 1, "A", "V").astype(object),
        **{name: data[name].astype(TABLE_DTYPES[name]) for name in TABLE_COLUMNS[2:]},
    })
    table = table.sort_values("ts", kind="stable", ignore_index=True)
    if table.empty:
        warnings.append("no packets between attacker and victim")
    return ParseResult(table, n_raw, attacker_ip, victim_ip, ip_inferred, warnings)
