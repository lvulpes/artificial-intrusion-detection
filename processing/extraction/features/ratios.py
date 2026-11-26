"""§4.2 attacker/victim direction ratios."""

import pandas as pd

from ._stats import is_attacker, safe_div


def compute(table: pd.DataFrame) -> dict[str, float]:
    a = is_attacker(table)
    ip_len = table["ip_len"].to_numpy(dtype="int64")
    return {
        "pkt_ratio_a_v": safe_div(a.sum(), (~a).sum()),
        "byte_ratio_a_v": safe_div(ip_len[a].sum(), ip_len[~a].sum()),
    }
