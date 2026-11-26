"""Pipeline parameters (§2.3), from defaults, an optional YAML file and CLI overrides."""

from dataclasses import dataclass, fields
from pathlib import Path

import yaml

from .columns import DEFAULT_BURST_THRESHOLDS_S


@dataclass(frozen=True)
class Config:
    burst_thresholds_s: tuple[float, ...] = DEFAULT_BURST_THRESHOLDS_S
    min_response_bytes: int = 0
    min_think_time_s: float = 0.0
    dedupe_tcp_retransmissions: bool = True

    def __post_init__(self) -> None:
        thresholds = tuple(float(t) for t in self.burst_thresholds_s)
        if not thresholds or any(t <= 0 for t in thresholds):
            raise ValueError("burst_thresholds_s must be a non-empty list of positive numbers")
        if len(set(thresholds)) != len(thresholds):
            raise ValueError("burst_thresholds_s must not contain duplicates")
        object.__setattr__(self, "burst_thresholds_s", thresholds)


def load_config(path: Path | None = None, **overrides: object) -> Config:
    """Defaults, then YAML values, then non-None overrides (CLI flags)."""
    values: dict[str, object] = {}
    if path is not None:
        loaded = yaml.safe_load(Path(path).read_text()) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}: expected a mapping of parameters")
        known = {f.name for f in fields(Config)}
        unknown = set(loaded) - known
        if unknown:
            raise ValueError(f"{path}: unknown parameters {sorted(unknown)}")
        values.update(loaded)
    values.update({k: v for k, v in overrides.items() if v is not None})
    return Config(**values)
