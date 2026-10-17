"""Phishing-email ML model: TF-IDF + simple engineered features.

The featurizer lives here (not in the training script) so that joblib can
unpickle it from the app.
"""
from __future__ import annotations

import re
from functools import lru_cache

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer

from explainability.shap_explainer import linear_shap, tree_shap
from utils.common import MODEL_DIR

MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
ENGINEERED = ["n_urls", "n_exclamations", "caps_ratio", "money_mentions", "log_length"]
ENGINEERED_LABELS = {
    "n_urls": "Number of links", "n_exclamations": "Exclamation marks", "caps_ratio": "Share of CAPITAL letters",
    "money_mentions": "Money / amount mentions", "log_length": "Message length",
}


def engineered(text: str) -> list[float]:
    letters = [c for c in text if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / max(len(letters), 1)
    return [
        float(min(len(URL_RE.findall(text)), 20)),
        float(min(text.count("!"), 30)),
        float(caps),
        float(min(len(re.findall(r"(\$|₹|rs\.?|inr|usd|dollars?|lakh|crore)\s?\d", text, re.I)), 20)),
        float(np.log1p(len(text))),
    ]


class EmailFeaturizer:
    def __init__(self, max_features: int = 3000):
        self.tfidf = TfidfVectorizer(max_features=max_features, ngram_range=(1, 2), min_df=3, sublinear_tf=True,
                                     stop_words="english", token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z]{2,}\b")
        self.eng_max = None

    def fit(self, texts):
        self.tfidf.fit(texts)
        E = np.array([engineered(t) for t in texts])
        self.eng_max = np.maximum(E.max(axis=0), 1e-9)
        return self

    def transform(self, texts):
        T = self.tfidf.transform(texts)
        E = np.array([engineered(t) for t in texts]) / self.eng_max
        return sparse.hstack([T, sparse.csr_matrix(E)]).tocsr()

    @property
    def feature_names(self) -> list[str]:
        return [f"word:{w}" for w in self.tfidf.get_feature_names_out()] + ENGINEERED


def feature_label(name: str) -> str:
    if name.startswith("word:"):
        return f"word '{name[5:]}'"
    return ENGINEERED_LABELS.get(name, name)


@lru_cache(maxsize=1)
def load_model() -> dict:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Email model not found at {MODEL_PATH}. Run: python ml/train_phishing_model.py")
    return joblib.load(MODEL_PATH)


def predict_proba_batch(texts: list[str]) -> np.ndarray:
    b = load_model()
    return b["model"].predict_proba(b["featurizer"].transform(texts))[:, 1]


def predict_email(text: str, explain: bool = True) -> dict:
    b = load_model()
    X = b["featurizer"].transform([text])
    prob = float(b["model"].predict_proba(X)[0, 1])
    shap_top = []
    if explain:
        names = b["featurizer"].feature_names
        x = X.toarray().ravel()
        if b["name"] == "LogisticRegression":
            shap_top = linear_shap(b["model"].coef_.ravel(), x, b["background_mean"], names, top_k=6)
        else:
            shap_top = tree_shap(b["model"], x, names, top_k=6)
    return {"probability": prob, "shap_top": shap_top, "model_name": b["name"], "dataset": b.get("dataset", "")}
