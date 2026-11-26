"""Feature groups (§4). Each module is a pure function over the per-packet table."""

from dataclasses import dataclass

import pandas as pd

from ..columns import feature_columns
from ..config import Config
from . import bursts, burstiness, duration, iat, rates, ratios, think


@dataclass
class FeatureResult:
    features: dict[str, float]
    turns: pd.DataFrame  # every turn, with a `kept` column for the step-3 filter
    n_turns: int
    n_retrans_dropped: int


def compute_all(table: pd.DataFrame, config: Config) -> FeatureResult:
    features: dict[str, float] = {}
    for module in (rates, ratios, duration, iat, burstiness):
        features.update(module.compute(table))
    for tau in config.burst_thresholds_s:
        features.update(bursts.compute(table, tau))

    data, n_dropped = think.data_packets(table, config.dedupe_tcp_retransmissions)
    turn_table = think.turns(data)
    turn_table["kept"] = think.keep_mask(turn_table, config.min_response_bytes, config.min_think_time_s)
    kept = turn_table[turn_table["kept"]]
    features.update(think.compute(kept))

    # Same order as the published column list, and a loud failure if a name drifts.
    columns = feature_columns(config.burst_thresholds_s)
    assert set(features) == set(columns), set(features) ^ set(columns)
    return FeatureResult({c: features[c] for c in columns}, turn_table, len(kept), n_dropped)
