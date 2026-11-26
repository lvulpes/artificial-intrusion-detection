"""§4.1 packet and byte rates over the session duration."""

import pandas as pd

from ._stats import is_attacker, safe_div, session_duration


def compute(table: pd.DataFrame) -> dict[str, float]:
    d = session_duration(table)
    a = is_attacker(table)
    ip_len = table["ip_len"].to_numpy(dtype="int64")
    return {
        "pkt_rate_all": safe_div(len(table), d),
        "pkt_rate_a": safe_div(a.sum(), d),
        "pkt_rate_v": safe_div((~a).sum(), d),
        "byte_rate_all": safe_div(ip_len.sum(), d),
        "byte_rate_a": safe_div(ip_len[a].sum(), d),
        "byte_rate_v": safe_div(ip_len[~a].sum(), d),
    }
