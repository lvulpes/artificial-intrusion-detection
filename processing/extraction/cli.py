"""`extract`: manifest -> features.csv, per-pcap cache and run log (§6)."""

import argparse
import json
import logging
import math
import re
import sys
import time
from pathlib import Path

import pandas as pd

from .columns import DIAG_COLUMNS, feature_columns
from .config import Config, load_config
from .features import compute_all
from .parse import TABLE_COLUMNS, parse_pcap

log = logging.getLogger("extraction")

REQUIRED_COLUMNS = ["pcap_path", "label", "run_id"]
LABELS = {"ai", "human"}
CACHE_VERSION = 1


def read_manifest(path: Path) -> pd.DataFrame:
    manifest = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = [c for c in REQUIRED_COLUMNS if c not in manifest.columns]
    if missing:
        raise ValueError(f"manifest is missing required columns {missing}")
    for col in REQUIRED_COLUMNS:
        if (manifest[col].str.strip() == "").any():
            raise ValueError(f"manifest has empty values in required column {col!r}")
    bad_labels = sorted(set(manifest["label"]) - LABELS)
    if bad_labels:
        raise ValueError(f"manifest has labels {bad_labels}; expected one of {sorted(LABELS)}")
    dupes = sorted(manifest.loc[manifest["run_id"].duplicated(), "run_id"])
    if dupes:
        raise ValueError(f"manifest has duplicate run_id values {dupes}")
    return manifest


def _cache_stem(run_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", run_id)


def _optional(row: pd.Series, col: str) -> str | None:
    value = str(row.get(col, "")).strip()
    return value or None


def _load_cached(meta_path: Path, packets_path: Path, pcap: Path, attacker: str | None, victim: str | None):
    """Cached (table, meta) if it was built from the same pcap and manifest IPs, else None."""
    if not (meta_path.exists() and packets_path.exists()):
        return None
    meta = json.loads(meta_path.read_text())
    source = {"cache_version": CACHE_VERSION, "pcap_path": str(pcap.resolve()),
              "pcap_mtime_ns": pcap.stat().st_mtime_ns, "manifest_attacker_ip": attacker,
              "manifest_victim_ip": victim}
    if any(meta.get(k) != v for k, v in source.items()):
        return None
    return pd.read_parquet(packets_path), meta


def process_one(row: pd.Series, manifest_dir: Path, config: Config, cache_dir: Path, reuse_cache: bool) -> dict:
    """Features and diagnostics for one manifest row. Raises on failure."""
    pcap = Path(row["pcap_path"])
    if not pcap.is_absolute():
        pcap = manifest_dir / pcap
    attacker, victim = _optional(row, "attacker_ip"), _optional(row, "victim_ip")
    stem = _cache_stem(row["run_id"])
    packets_path = cache_dir / f"{stem}.packets.parquet"
    turns_path = cache_dir / f"{stem}.turns.csv"
    meta_path = cache_dir / f"{stem}.meta.json"

    cached = _load_cached(meta_path, packets_path, pcap, attacker, victim) if reuse_cache else None
    if cached is not None:
        table, meta = cached
        log.info("%s: using cached packet table", row["run_id"])
    else:
        parsed = parse_pcap(pcap, attacker, victim)
        table = parsed.table
        meta = {
            "cache_version": CACHE_VERSION,
            "pcap_path": str(pcap.resolve()),
            "pcap_mtime_ns": pcap.stat().st_mtime_ns,
            "manifest_attacker_ip": attacker,
            "manifest_victim_ip": victim,
            "attacker_ip": parsed.attacker_ip,
            "victim_ip": parsed.victim_ip,
            "ip_inferred": parsed.ip_inferred,
            "n_packets_raw": parsed.n_packets_raw,
            "warnings": parsed.warnings,
        }
        table[TABLE_COLUMNS].to_parquet(packets_path, index=False)
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    result = compute_all(table, config)
    result.turns.to_csv(turns_path, index=False)

    warnings = list(meta["warnings"])
    for warning in warnings:
        log.warning("%s: %s", row["run_id"], warning)
    return {
        **result.features,
        "diag_n_packets_raw": meta["n_packets_raw"],
        "diag_n_packets_filtered": len(table),
        "diag_attacker_ip": meta["attacker_ip"],
        "diag_victim_ip": meta["victim_ip"],
        "diag_ip_inferred": meta["ip_inferred"],
        "diag_n_turns": result.n_turns,
        "diag_n_retrans_dropped": result.n_retrans_dropped,
        "diag_warnings": " | ".join(warnings),
    }


def run(manifest_path: Path, out_dir: Path, config: Config, reuse_cache: bool = False) -> pd.DataFrame:
    manifest = read_manifest(manifest_path)
    cache_dir = out_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    features = feature_columns(config.burst_thresholds_s)
    log.info("config: %s", config)
    log.info("manifest: %s (%d pcaps)", manifest_path, len(manifest))

    rows, failed = [], []
    for i, row in manifest.iterrows():
        start = time.monotonic()
        try:
            values = process_one(row, manifest_path.parent, config, cache_dir, reuse_cache)
            log.info("[%d/%d] %s: %d packets, %d turns (%.1fs)", i + 1, len(manifest), row["run_id"],
                     values["diag_n_packets_filtered"], values["diag_n_turns"], time.monotonic() - start)
        except Exception as exc:  # one bad file must not abort the batch
            log.error("[%d/%d] %s: FAILED: %s: %s", i + 1, len(manifest), row["run_id"], type(exc).__name__, exc)
            failed.append(row["run_id"])
            values = {c: math.nan for c in features + DIAG_COLUMNS}
            values["diag_warnings"] = f"ERROR: {type(exc).__name__}: {exc}"
        rows.append(values)

    computed = pd.DataFrame(rows, columns=features + DIAG_COLUMNS)
    passthrough = manifest.drop(columns=[c for c in manifest.columns if c in computed.columns])
    out = pd.concat([passthrough.reset_index(drop=True), computed], axis=1)
    out.to_csv(out_dir / "features.csv", index=False)

    log.info("done: %d processed, %d failed%s", len(manifest) - len(failed), len(failed),
             f" ({', '.join(failed)})" if failed else "")
    return out


def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for handler in (logging.FileHandler(log_path, mode="w"), logging.StreamHandler(sys.stderr)):
        handler.setFormatter(fmt)
        log.addHandler(handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pre-process.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract", help="extract one feature row per pcap in the manifest")
    extract.add_argument("--manifest", type=Path, required=True, help="manifest CSV (§2.2)")
    extract.add_argument("--out", type=Path, required=True, help="output directory")
    extract.add_argument("--config", type=Path, help="YAML config (§2.3); flags below override it")
    extract.add_argument("--burst-thresholds", type=float, nargs="+", metavar="SECONDS",
                         dest="burst_thresholds_s")
    extract.add_argument("--min-response-bytes", type=int)
    extract.add_argument("--min-think-time", type=float, dest="min_think_time_s")
    extract.add_argument("--dedupe-tcp-retransmissions", action=argparse.BooleanOptionalAction, default=None)
    extract.add_argument("--reuse-cache", action="store_true",
                         help="reuse cached packet tables instead of re-parsing unchanged pcaps")
    args = parser.parse_args(argv)

    config = load_config(
        args.config,
        burst_thresholds_s=args.burst_thresholds_s,
        min_response_bytes=args.min_response_bytes,
        min_think_time_s=args.min_think_time_s,
        dedupe_tcp_retransmissions=args.dedupe_tcp_retransmissions,
    )
    _setup_logging(args.out / "run.log")
    out = run(args.manifest, args.out, config, reuse_cache=args.reuse_cache)
    return 1 if out["diag_warnings"].astype(str).str.startswith("ERROR:").all() else 0
