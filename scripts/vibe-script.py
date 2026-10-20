#!/usr/bin/env python3
"""
Inter-Packet Arrival Time (IPAT) Analysis Script (vibe-script.py)
Calculates and visualizes IPAT statistics from a PCAP file using Scapy.
"""

import argparse
import sys
from typing import List, Dict, Tuple
import statistics
from collections import defaultdict

try:
    from scapy.all import PcapReader, IP, TCP, UDP
except ImportError:
    print("Error: Scapy is not installed. Please install it using 'pip install scapy'.", file=sys.stderr)
    sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Calculate and visualize Inter-Packet Arrival Time (IPAT) from a PCAP file."
    )
    parser.add_argument(
        "pcap_file",
        type=str,
        help="Path to the PCAP file to analyze (e.g., ../pcaps/test-pcap-2.pcap)"
    )
    parser.add_argument(
        "--per-flow",
        action="store_true",
        help="Calculate IPAT per transport flow (5-tuple) in addition to global IPAT."
    )
    return parser.parse_args()


def generate_ascii_histogram(data: List[float], bins: int = 10, width: int = 40) -> str:
    """Generates an ASCII histogram for a list of numerical values."""
    if not data:
        return "No data available for visualization."
    
    min_val = min(data)
    max_val = max(data)
    
    if min_val == max_val:
        return f"All IPAT values are identical: {min_val:.4f} ms"
    
    bin_width = (max_val - min_val) / bins
    bin_counts = [0] * bins
    
    for val in data:
        idx = int((val - min_val) / bin_width)
        if idx >= bins:
            idx = bins - 1
        bin_counts[idx] += 1
        
    max_count = max(bin_counts) if bin_counts else 1
    
    lines = []
    for i in range(bins):
        b_start = min_val + i * bin_width
        b_end = b_start + bin_width
        count = bin_counts[i]
        bar_len = int((count / max_count) * width) if max_count > 0 else 0
        bar = "#" * bar_len
        lines.append(f"{b_start:9.2f}ms - {b_end:9.2f}ms | {bar} ({count})")
        
    return "\n".join(lines)


def analyze_pcap(pcap_path: str, per_flow: bool = False) -> None:
    print(f"[*] Loading and analyzing PCAP: {pcap_path}")
    
    timestamps: List[float] = []
    flow_timestamps: Dict[Tuple, List[float]] = defaultdict(list)
    
    packet_count = 0
    non_ip_count = 0
    
    try:
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                if hasattr(pkt, 'time'):
                    t = float(pkt.time)
                    timestamps.append(t)
                    
                    if per_flow and IP in pkt:
                        ip_layer = pkt[IP]
                        proto = ip_layer.proto
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        src_port = 0
                        dst_port = 0
                        if TCP in pkt:
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                        elif UDP in pkt:
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport
                        
                        # Canonical flow key (ignoring direction or directional)
                        flow_key = (src_ip, dst_ip, proto, src_port, dst_port)
                        flow_timestamps[flow_key].append(t)
    except Exception as e:
        print(f"[-] Error reading PCAP file: {e}", file=sys.stderr)
        sys.exit(1)
        
    if len(timestamps) < 2:
        print(f"[-] PCAP contains fewer than 2 timestamped packets ({packet_count} packets found). Cannot calculate IPAT.")
        return

    print(f"[+] Successfully read {packet_count} packets.")
    
    # Calculate global IPAT in milliseconds
    # Sort timestamps just in case PCAP reader order is out of sequence
    timestamps.sort()
    ipats = [(timestamps[i] - timestamps[i - 1]) * 1000.0 for i in range(1, len(timestamps))]
    
    if not ipats:
        print("[-] No valid IPAT intervals calculated.")
        return

    # Compute Statistics
    mean_ipat = statistics.mean(ipats)
    median_ipat = statistics.median(ipats)
    min_ipat = min(ipats)
    max_ipat = max(ipats)
    stdev_ipat = statistics.stdev(ipats) if len(ipats) > 1 else 0.0
    
    # Percentiles
    sorted_ipats = sorted(ipats)
    p25 = sorted_ipats[int(len(sorted_ipats) * 0.25)]
    p75 = sorted_ipats[int(len(sorted_ipats) * 0.75)]
    p95 = sorted_ipats[int(len(sorted_ipats) * 0.95)]
    
    print("\n" + "=" * 60)
    print("GLOBAL INTER-PACKET ARRIVAL TIME (IPAT) STATISTICS")
    print("=" * 60)
    print(f"Total Packets Analyzed      : {packet_count}")
    print(f"Total Intervals (IPATs)     : {len(ipats)}")
    print(f"Mean IPAT                   : {mean_ipat:.4f} ms")
    print(f"Median IPAT (P50)           : {median_ipat:.4f} ms")
    print(f"Standard Deviation          : {stdev_ipat:.4f} ms")
    print(f"Min IPAT                    : {min_ipat:.4f} ms")
    print(f"25th Percentile (P25)       : {p25:.4f} ms")
    print(f"75th Percentile (P75)       : {p75:.4f} ms")
    print(f"95th Percentile (P95)       : {p95:.4f} ms")
    print(f"Max IPAT                    : {max_ipat:.4f} ms")
    print("=" * 60)
    
    print("\n[Visual Illustration: Global IPAT Distribution Histogram]")
    print(generate_ascii_histogram(ipats, bins=10, width=50))
    print("=" * 60)
    
    if per_flow and flow_timestamps:
        print("\n" + "=" * 60)
        print("TOP FLOWS BY PACKET COUNT & MEAN IPAT")
        print("=" * 60)
        sorted_flows = sorted(flow_timestamps.items(), key=lambda x: len(x[1]), reverse=True)
        for flow, f_times in sorted_flows[:5]:
            if len(f_times) < 2:
                continue
            f_times.sort()
            f_ipats = [(f_times[i] - f_times[i - 1]) * 1000.0 for i in range(1, len(f_times))]
            f_mean = statistics.mean(f_ipats)
            src_ip, dst_ip, proto, sport, dport = flow
            proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto))
            print(f"Flow: {src_ip}:{sport} -> {dst_ip}:{dport} ({proto_name})")
            print(f"  Packets: {len(f_times)} | Mean IPAT: {f_mean:.4f} ms | Max IPAT: {max(f_ipats):.4f} ms")
        print("=" * 60)


if __name__ == "__main__":
    args = parse_arguments()
    analyze_pcap(args.pcap_file, per_flow=args.per_flow)
