"""Load the trained URL model and score a single URL (+ SHAP top features)."""
from __future__ import annotations

from functools import lru_cache

import joblib
import numpy as np

from explainability.shap_explainer import tree_shap
from utils.common import MODEL_DIR
from utils.feature_extraction import FEATURE_NAMES, feature_vector

MODEL_PATH = MODEL_DIR / "url_model.joblib"


@lru_cache(maxsize=1)
def load_model() -> dict:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"URL model not found at {MODEL_PATH}. Run: python ml/train_url_model.py")
    bundle = joblib.load(MODEL_PATH)
    if hasattr(bundle["model"], "n_jobs"):
        bundle["model"].n_jobs = 1  # single-row predictions: thread start-up costs more than it saves
    return bundle


def predict_proba_batch(urls: list[str]) -> np.ndarray:
    bundle = load_model()
    X = np.array([feature_vector(u) for u in urls], dtype=float)
    return bundle["model"].predict_proba(X)[:, 1]


def predict_url(url: str, explain: bool = True) -> dict:
    bundle = load_model()
    x = np.array(feature_vector(url), dtype=float)
    prob = float(bundle["model"].predict_proba(x.reshape(1, -1))[0, 1])
    shap_top = tree_shap(bundle["model"], x, FEATURE_NAMES, top_k=5) if explain else []
    return {"probability": prob, "shap_top": shap_top, "model_name": bundle["name"],
            "dataset": bundle.get("dataset", "")}
