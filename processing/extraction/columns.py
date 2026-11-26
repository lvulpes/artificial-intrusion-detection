"""Output column names, grouped so the modelling stage can select features by group."""

from collections.abc import Sequence

DEFAULT_BURST_THRESHOLDS_S: tuple[float, ...] = (1.0, 5.0)

RATES = ["pkt_rate_all", "pkt_rate_a", "pkt_rate_v", "byte_rate_all", "byte_rate_a", "byte_rate_v"]
RATIOS = ["pkt_ratio_a_v", "byte_ratio_a_v"]
DURATION = ["duration_s"]
IAT = [
    f"iat_{subset}_{stat}"
    for subset in ("all", "a")
    for stat in ("min", "max", "mean", "median", "std")
]
BURSTINESS = ["burstiness"]
THINK = ["think_median", "think_cv", "think_size_corr"]

BURST_STATS = [
    "n_bursts",
    "bursts_per_min",
    "pkts_per_burst",
    "bytes_per_burst",
    "idle_min",
    "idle_max",
    "idle_mean",
    "idle_median",
    "duty_cycle",
]


def tau_suffix(tau: float) -> str:
    """`_t1s` for 1.0, `_t0.5s` for 0.5."""
    return f"_t{tau:g}s"


def burst_columns(tau: float) -> list[str]:
    return [f"{stat}{tau_suffix(tau)}" for stat in BURST_STATS]


def feature_groups(burst_thresholds_s: Sequence[float] = DEFAULT_BURST_THRESHOLDS_S) -> dict[str, list[str]]:
    """Feature names by group, in output order (§4)."""
    groups = {
        "rates": RATES,
        "ratios": RATIOS,
        "duration": DURATION,
        "iat": IAT,
        "burstiness": BURSTINESS,
    }
    for tau in burst_thresholds_s:
        groups[f"bursts{tau_suffix(tau)}"] = burst_columns(tau)
    groups["think"] = THINK
    return groups


def feature_columns(burst_thresholds_s: Sequence[float] = DEFAULT_BURST_THRESHOLDS_S) -> list[str]:
    return [name for names in feature_groups(burst_thresholds_s).values() for name in names]


# Defaults: 41 features in groups rates, ratios, duration, iat, burstiness, bursts_t1s, bursts_t5s, think.
FEATURE_GROUPS: dict[str, list[str]] = feature_groups()
FEATURE_COLUMNS: list[str] = feature_columns()

# Not features: never feed these to a model.
DIAG_COLUMNS = [
    "diag_n_packets_raw",
    "diag_n_packets_filtered",
    "diag_attacker_ip",
    "diag_victim_ip",
    "diag_ip_inferred",
    "diag_n_turns",
    "diag_n_retrans_dropped",
    "diag_warnings",
]
