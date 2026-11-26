"""§4.4 inter-arrival time statistics, over all packets and over attacker packets only."""

import numpy as np
import pandas as pd

from ._stats import is_attacker, summary

STATS = ("min", "max", "mean", "median", "std")


def compute(table: pd.DataFrame) -> dict[str, float]:
    ts = table["ts"].to_numpy()
    return {
        **summary(np.diff(ts), "iat_all", STATS),
        **summary(np.diff(ts[is_attacker(table)]), "iat_a", STATS),
    }
