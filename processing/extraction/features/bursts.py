"""§4.5 burst structure of the all-packet stream for one idle threshold tau."""

import numpy as np
import pandas as pd

from ..columns import tau_suffix
from ._stats import NAN, safe_div, session_duration, summary


def compute(table: pd.DataFrame, tau: float) -> dict[str, float]:
    sfx = tau_suffix(tau)
    ts = table["ts"].to_numpy()
    d = session_duration(table)
    n = len(ts)

    gaps = np.diff(ts)
    new_burst = gaps > tau  # strictly greater: a gap of exactly tau stays inside the burst
    idle = gaps[new_burst]
    n_bursts = int(new_burst.sum()) + 1 if n else 0

    if n:
        starts = np.concatenate(([0], np.flatnonzero(new_burst) + 1))
        ends = np.concatenate((starts[1:] - 1, [n - 1]))
        burst_bytes = np.add.reduceat(table["ip_len"].to_numpy(dtype="int64"), starts)
        busy_time = float(np.sum(ts[ends] - ts[starts]))
        bytes_per_burst = float(np.mean(burst_bytes))
    else:
        busy_time = bytes_per_burst = NAN

    idle_stats = summary(idle, "idle", ("min", "max", "mean", "median"))
    return {
        f"n_bursts{sfx}": n_bursts,
        f"bursts_per_min{sfx}": safe_div(n_bursts, d / 60),
        f"pkts_per_burst{sfx}": safe_div(n, n_bursts),
        f"bytes_per_burst{sfx}": bytes_per_burst,
        **{f"{name}{sfx}": value for name, value in idle_stats.items()},
        f"duty_cycle{sfx}": safe_div(busy_time, d),
    }
