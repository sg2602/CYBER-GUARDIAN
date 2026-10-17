"""SHAP explanations for the ML modules (URL and email) only.

Rule-based modules are explained by their human-readable rule findings; SHAP is
deliberately NOT applied to them (there is no model to explain).
"""
from __future__ import annotations

import numpy as np

_EXPLAINERS: dict[int, object] = {}


def _tree_explainer(model):
    import shap
    key = id(model)
    if key not in _EXPLAINERS:
        _EXPLAINERS[key] = shap.TreeExplainer(model)
    return _EXPLAINERS[key]


def _class1(values) -> np.ndarray:
    """Normalise SHAP output to a 1-D array for the positive class of one row."""
    v = values
    if isinstance(v, list):  # older shap: list per class
        v = v[1]
    v = np.asarray(v)
    if v.ndim == 3:  # (rows, features, classes)
        v = v[0, :, 1]
    elif v.ndim == 2:
        v = v[0]
    return v


def tree_shap(model, x_row: np.ndarray, feature_names: list[str], top_k: int = 5) -> list[tuple[str, float]]:
    """TreeExplainer SHAP values for a single row; returns top-k by |value| (positive = towards phishing)."""
    exp = _tree_explainer(model)
    vals = _class1(exp.shap_values(np.asarray(x_row, dtype=float).reshape(1, -1)))
    order = np.argsort(-np.abs(vals))[:top_k]
    return [(feature_names[i], float(vals[i])) for i in order]


def linear_shap(coef: np.ndarray, x_row: np.ndarray, background_mean: np.ndarray, feature_names: list[str],
                top_k: int = 5) -> list[tuple[str, float]]:
    """Exact SHAP values of a linear (logistic) model in log-odds space,
    assuming feature independence: phi_i = w_i * (x_i - E[x_i])."""
    x = np.asarray(x_row).ravel()
    vals = np.asarray(coef).ravel() * (x - np.asarray(background_mean).ravel())
    nz = np.nonzero(vals)[0]
    order = nz[np.argsort(-np.abs(vals[nz]))][:top_k]
    return [(feature_names[i], float(vals[i])) for i in order]


def plain_english(name: str, value: float, labels: dict[str, str] | None = None) -> str:
    label = (labels or {}).get(name, name.replace("_", " "))
    direction = "raised" if value > 0 else "lowered"
    return f"{label} {direction} the phishing estimate ({value:+.2f})"


def to_points(shap_top: list[tuple[str, float]], ml_points: float) -> list[tuple[str, float]]:
    """Split the ML module deficit ('points lost', C3) across positive SHAP contributors."""
    pos = [(n, v) for n, v in shap_top if v > 0]
    tot = sum(v for _, v in pos)
    if tot <= 0:
        return []
    return [(n, ml_points * v / tot) for n, v in pos]
