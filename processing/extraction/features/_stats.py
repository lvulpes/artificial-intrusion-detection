"""Shared helpers. Std is population std (ddof=0) everywhere (§3.3); undefined values are NaN."""

import numpy as np
import pandas as pd

NAN = float("nan")


def safe_div(num: float, den: float) -> float:
    if den == 0 or np.isnan(den):
        return NAN
    return float(num / den)


def summary(values: np.ndarray, prefix: str, stats: tuple[str, ...]) -> dict[str, float]:
    """{prefix}_{stat} for each requested stat of `values`; all NaN when `values` is empty."""
    if len(values) == 0:
        return {f"{prefix}_{s}": NAN for s in stats}
    funcs = {
        "min": np.min,
        "max": np.max,
        "mean": np.mean,
        "median": np.median,
        "std": lambda x: np.std(x, ddof=0),
    }
    return {f"{prefix}_{s}": float(funcs[s](values)) for s in stats}


def session_duration(table: pd.DataFrame) -> float:
    """D = ts_last - ts_first over the filtered (time-sorted) table; NaN if empty."""
    if table.empty:
        return NAN
    ts = table["ts"].to_numpy()
    return float(ts[-1] - ts[0])


def is_attacker(table: pd.DataFrame) -> np.ndarray:
    return table["dir"].to_numpy() == "A"
