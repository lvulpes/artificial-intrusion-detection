"""§4.3 session duration."""

import pandas as pd

from ._stats import session_duration


def compute(table: pd.DataFrame) -> dict[str, float]:
    return {"duration_s": session_duration(table)}
