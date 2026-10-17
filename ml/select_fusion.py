"""Choose the rule+ML fusion method for the URL and email modules on OUT-OF-FOLD data.

    python ml/select_fusion.py

For each module we take the TRAINING portion only (everything not in the held-out
test split), get 5-fold out-of-fold ML probabilities with the same model type as
the deployed model, compute the rule deficit for every example, and evaluate
candidate fusion methods at the HIGH threshold (module score < 60).  The method
with the best F1 is written to ml/models/fusion.json.  The test split is never used.

Outputs: ml/models/fusion.json, results/fusion_selection.csv
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.base import clone  # noqa: E402
from sklearn.model_selection import StratifiedKFold  # noqa: E402

from ml.phishing_model import EmailFeaturizer  # noqa: E402
from utils.common import DATA_DIR, MODEL_DIR, RESULTS_DIR  # noqa: E402
from utils.feature_extraction import feature_vector  # noqa: E402
from utils.fusion import FUSION_PATH, fuse  # noqa: E402

SEED = 42
CANDIDATES = [("linear", w) for w in (0.3, 0.4, 0.5, 0.6)] + [("max", None), ("noisy_or", None)]


def oof_url(train: pd.DataFrame, model) -> np.ndarray:
    X = np.array([feature_vector(u) for u in train.url.astype(str)], dtype=float)
    y = train.label.values
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(5, shuffle=True, random_state=SEED).split(X, y):
        m = clone(model).fit(X[tr], y[tr])
        oof[va] = m.predict_proba(X[va])[:, 1]
    return oof


def oof_email(train: pd.DataFrame, model) -> np.ndarray:
    texts = train.text.astype(str).values
    y = train.label.values
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(5, shuffle=True, random_state=SEED).split(texts, y):
        f = EmailFeaturizer().fit(texts[tr])
        m = clone(model).fit(f.transform(texts[tr]), y[tr])
        oof[va] = m.predict_proba(f.transform(texts[va]))[:, 1]
    return oof


def evaluate(module: str, y, rule_def, ml_def) -> list[dict]:
    rows = []
    for method, w in CANDIDATES:
        deficits = np.array([sum(fuse(r, m, method, w if w is not None else 0.5)) for r, m in zip(rule_def, ml_def)])
        pred = deficits > 40  # score < 60
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
        prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)
        rows.append({"module": module, "method": method, "rule_weight": w, "precision": round(prec, 4),
                     "recall": round(rec, 4), "f1": round(f1, 4), "fpr": round(fp / max((y == 0).sum(), 1), 4),
                     "n": len(y)})
    # reference rows: each detector alone
    for name, d in (("rules_only", rule_def), ("ml_only", ml_def)):
        pred = np.asarray(d) > 40
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
        prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
        rows.append({"module": module, "method": name, "rule_weight": None, "precision": round(prec, 4),
                     "recall": round(rec, 4), "f1": round(2 * prec * rec / max(prec + rec, 1e-9), 4),
                     "fpr": round(fp / max((y == 0).sum(), 1), 4), "n": len(y)})
    return rows


def main():
    from modules.email_analyzer import analyze_email
    from modules.url_scanner import is_official_domain, rule_findings

    all_rows, chosen = [], {}
    # ---- URL ----
    d = pd.read_csv(DATA_DIR / "url_dataset.csv")
    test = set(pd.read_csv(DATA_DIR / "url_test_split.csv").url)
    train = d[~d.url.isin(test)].sample(12000, random_state=SEED).reset_index(drop=True)
    model = joblib.load(MODEL_DIR / "url_model.joblib")["model"]
    p = oof_url(train, model)
    rule_def, ml_def = [], []
    for u, pr in zip(train.url.astype(str), p):
        f, info = rule_findings(u)
        rule_def.append(min(100.0, sum(x["points_lost"] for x in f)))
        ml_def.append(pr * 100 * (0.3 if is_official_domain(info["parsed"]["registered_domain"]) else 1.0))
    rows = evaluate("url", train.label.values, rule_def, ml_def)
    all_rows += rows
    # ---- Email ----
    e = pd.read_csv(DATA_DIR / "email_dataset.csv")
    etest = set(pd.read_csv(DATA_DIR / "email_test_split.csv").text)
    etrain = e[~e.text.isin(etest)].reset_index(drop=True)
    emodel = joblib.load(MODEL_DIR / "phishing_model.joblib")["model"]
    pe = oof_email(etrain, emodel)
    erule = [100 - analyze_email(t, use_ml=False, explain=False)["score"] for t in etrain.text.astype(str)]
    all_rows += evaluate("email", etrain.label.values, erule, pe * 100)

    df = pd.DataFrame(all_rows)
    df.to_csv(RESULTS_DIR / "fusion_selection.csv", index=False)
    for mod in ("url", "email"):
        cand = df[(df.module == mod) & df.method.isin(["linear", "max", "noisy_or"])]
        best = cand.sort_values(["f1", "precision"], ascending=False).iloc[0]
        chosen[mod] = {"method": best.method, "rule_weight": None if pd.isna(best.rule_weight) else float(best.rule_weight),
                       "selected_on": "5-fold out-of-fold predictions on the training split",
                       "oof_f1": float(best.f1), "oof_precision": float(best.precision), "oof_recall": float(best.recall)}
        if chosen[mod]["rule_weight"] is None:
            chosen[mod]["rule_weight"] = 0.5
    FUSION_PATH.write_text(json.dumps(chosen, indent=2))
    print(df.to_string(index=False))
    print(json.dumps(chosen, indent=2))


if __name__ == "__main__":
    main()
