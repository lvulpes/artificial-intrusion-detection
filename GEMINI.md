# Project Context: Academic Network Security Research

## Primary Goal
Assist in writing, refactoring, and debugging Python scripts for offline and real-time PCAP/PCAPNG packet analysis, protocol extraction, and network forensics.

## Environment & Tooling
- **OS**: Fedora Linux x86_64
- **Python**: 3.11+
- **Primary Libraries**: `scapy`, `pyshark`, `dpkt`, `dpkt`, `pandas`, `ja4` / custom transport fingerprinting modules
- **Editor Context**: Neovim (LazyVim) - keep responses formatted for direct integration without extra wrapper cruft.

## Engineering Rules
1. **Prefer Config File Edits Over `sed`**: Provide clear block edits for files or explicit script modifications. Avoid obscure shell one-liners.
2. **Explicit Packet Handling**: Write readable, modular code instead of complex single-line list comprehensions when parsing layers or protocol fields.
3. **Performance Awareness**: Large PCAP files consume substantial memory. For bulk analysis, prefer iterator/generator patterns (`PcapReader` in Scapy, `FileCapture` in PyShark with display filters, or native `dpkt`) over loading full datasets into memory at once.
4. **Verification**: Include exact terminal commands (e.g., `tshark`, `tcpdump`, or verification scripts) to test and confirm that generated Python code correctly processes the target traffic.

## Code Output Conventions
- Fully typed Python functions using standard `typing` / Python 3.10+ type hints.
- Standalone runnable scripts or importable modules with `if __name__ == "__main__":` blocks handling command-line arguments using `argparse`.
