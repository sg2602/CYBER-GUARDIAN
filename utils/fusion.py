"""Rule + ML evidence fusion for the hybrid modules (URL, email).

Both inputs are deficits in [0, 100] ("points lost").  The fused deficit is split
back into a rule part and an ML part so that the module's findings still sum
exactly to 100 - score (score traceability, C3).

The method per module is chosen by ml/select_fusion.py on OUT-OF-FOLD
predictions of the training split (never on the test split) and stored in
ml/models/fusion.json.  If that file is missing, DEFAULT_FUSION is used.
"""
from __future__ import annotations

import json
from functools import lru_cache

from utils.common import MODEL_DIR

FUSION_PATH = MODEL_DIR / "fusion.json"
DEFAULT_FUSION = {"url": {"method": "linear", "rule_weight": 0.55}, "email": {"method": "linear", "rule_weight": 0.6}}
METHODS = ("linear", "max", "noisy_or")


@lru_cache(maxsize=1)
def config() -> dict:
    if FUSION_PATH.exists():
        try:
            return {**DEFAULT_FUSION, **json.loads(FUSION_PATH.read_text())}
        except (ValueError, OSError):
            pass
    return DEFAULT_FUSION


def fuse(rule_def: float, ml_def: float, method: str, rule_weight: float = 0.5) -> tuple[float, float]:
    """Return (rule_part, ml_part); rule_part + ml_part = fused deficit."""
    r, m = max(0.0, min(100.0, rule_def)), max(0.0, min(100.0, ml_def))
    if method == "linear":
        return rule_weight * r, (1 - rule_weight) * m
    if method == "max":
        total = max(r, m)
    elif method == "noisy_or":
        total = 100.0 * (1 - (1 - r / 100.0) * (1 - m / 100.0))
    else:
        raise ValueError(method)
    if r + m == 0:
        return 0.0, 0.0
    return total * r / (r + m), total * m / (r + m)


def fuse_module(module: str, rule_def: float, ml_def: float) -> tuple[float, float]:
    c = config()[module]
    return fuse(rule_def, ml_def, c["method"], c.get("rule_weight", 0.5))


def describe(module: str) -> str:
    c = config()[module]
    return f"linear (rules {c['rule_weight']:.0%} / ML {1 - c['rule_weight']:.0%})" if c["method"] == "linear" else c["method"]
