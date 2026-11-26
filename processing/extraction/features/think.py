"""§4.7 think time: delay between the victim's last data and the attacker's next data.

Data packets of all connections are merged into one session-level stream (deliberately not per
connection); a turn is every V-run -> A-run transition.
"""

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from ..parse import PROTO_TCP, PROTO_UDP
from ._stats import NAN, safe_div

TURN_COLUMNS = ["ts", "think_time", "response_bytes"]
DEDUPE_KEY = ["dir", "sport", "dport", "tcp_seq", "payload_len"]  # dir fixes (src, dst)


def data_packets(table: pd.DataFrame, dedupe_tcp_retransmissions: bool) -> tuple[pd.DataFrame, int]:
    """Step 1: TCP/UDP packets with payload, minus TCP retransmissions. Returns (data, n_dropped)."""
    data = table[(table["payload_len"] > 0) & table["proto"].isin((PROTO_TCP, PROTO_UDP))]
    if not dedupe_tcp_retransmissions:
        return data, 0
    # Packets are time-sorted, so duplicated() keeps the first occurrence.
    retrans = (data["proto"] == PROTO_TCP) & (data["tcp_seq"] >= 0) & data.duplicated(DEDUPE_KEY)
    return data[~retrans], int(retrans.sum())


def turns(data: pd.DataFrame) -> pd.DataFrame:
    """Step 2: one row per V-run -> A-run transition, `ts` = first packet of the A-run."""
    ts = data["ts"].to_numpy()
    is_a = data["dir"].to_numpy() == "A"
    payload = data["payload_len"].to_numpy(dtype="int64")
    if len(ts) < 2:
        return pd.DataFrame({c: pd.Series(dtype="float64") for c in TURN_COLUMNS})

    run_starts = np.concatenate(([0], np.flatnonzero(is_a[1:] != is_a[:-1]) + 1))
    run_bytes = np.add.reduceat(payload, run_starts)
    # Runs alternate direction, so every A-run after the first run follows a V-run.
    turn_runs = np.flatnonzero(is_a[run_starts])
    turn_runs = turn_runs[turn_runs > 0]
    a_first = run_starts[turn_runs]
    return pd.DataFrame({
        "ts": ts[a_first],
        "think_time": ts[a_first] - ts[a_first - 1],
        "response_bytes": run_bytes[turn_runs - 1],
    })


def keep_mask(turn_table: pd.DataFrame, min_response_bytes: float, min_think_time_s: float) -> pd.Series:
    """Step 3: turns that pass the response-size and think-time minimums."""
    return (turn_table["response_bytes"] >= min_response_bytes) & (turn_table["think_time"] >= min_think_time_s)


def compute(kept_turns: pd.DataFrame) -> dict[str, float]:
    think = kept_turns["think_time"].to_numpy(dtype="float64")
    size = kept_turns["response_bytes"].to_numpy(dtype="float64")
    n = len(think)

    median = float(np.median(think)) if n else NAN
    cv = safe_div(float(np.std(think, ddof=0)), float(np.mean(think))) if n >= 2 else NAN
    if n >= 3 and np.ptp(think) > 0 and np.ptp(size) > 0:
        corr = float(spearmanr(size, think).statistic)
    else:
        corr = NAN
    return {"think_median": median, "think_cv": cv, "think_size_corr": corr}
