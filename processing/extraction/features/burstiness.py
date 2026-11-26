"""§4.4 burstiness B = (sigma - mu) / (sigma + mu) of the all-packet IAT sequence."""

import numpy as np
import pandas as pd

from ._stats import NAN, safe_div


def compute(table: pd.DataFrame) -> dict[str, float]:
    iat = np.diff(table["ts"].to_numpy())
    if len(iat) == 0:
        return {"burstiness": NAN}
    mu, sigma = float(np.mean(iat)), float(np.std(iat, ddof=0))
    return {"burstiness": safe_div(sigma - mu, sigma + mu)}
