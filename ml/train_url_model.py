"""Train the URL phishing model: Random Forest vs XGBoost, pick best by F1.

    python ml/train_url_model.py            # uses data/url_dataset.csv
    python ml/train_url_model.py --data path/to/your.csv   (columns: url,label)

Outputs: ml/models/url_model.joblib, results/ml_metrics.csv (rows task=url),
results/confusion_url_<model>.png, data/url_test_split.csv (held-out test set).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from ml.metrics_utils import evaluate, save_confusion, write_metrics  # noqa: E402
from utils.common import DATA_DIR, MODEL_DIR, RESULTS_DIR  # noqa: E402
from utils.feature_extraction import FEATURE_NAMES, feature_vector  # noqa: E402

SEED = 42


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DATA_DIR / "url_dataset.csv"))
    args = ap.parse_args()
    df = pd.read_csv(args.data)
    dataset_name = Path(args.data).name
    if "source" in df.columns:
        dataset_name += " (" + " + ".join(sorted(df.source.unique())) + ")"
    print(f"Loaded {len(df)} URLs from {args.data}")
    t = time.time()
    X = np.array([feature_vector(u) for u in df.url.astype(str)], dtype=float)
    y = df.label.astype(int).values
    print(f"Extracted {X.shape[1]} features in {time.time() - t:.1f}s")
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=0.2, stratify=y, random_state=SEED)
    df.iloc[te][["url", "label"] + (["source"] if "source" in df.columns else [])].to_csv(
        DATA_DIR / "url_test_split.csv", index=False)

    candidates = {
        "RandomForest": RandomForestClassifier(n_estimators=150, min_samples_leaf=3, max_depth=24, n_jobs=-1,
                                               class_weight="balanced", random_state=SEED),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
                                 colsample_bytree=0.9, eval_metric="logloss", n_jobs=2, random_state=SEED),
    }
    rows, fitted = [], {}
    for name, model in candidates.items():
        t = time.time()
        model.fit(X[tr], y[tr])
        pred = model.predict(X[te])
        m = evaluate(y[te], pred)
        m.update(task="url", model=name, dataset=dataset_name, n_train=len(tr), n_test=len(te),
                 train_seconds=round(time.time() - t, 1))
        rows.append(m)
        fitted[name] = model
        save_confusion(y[te], pred, RESULTS_DIR / f"confusion_url_{name}.png",
                       f"URL model - {name}", labels=["Legitimate", "Phishing"])
        print(f"{name}: acc={m['accuracy']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} f1={m['f1']:.4f}")
    best = max(rows, key=lambda r: r["f1"])["model"]
    for r in rows:
        r["selected"] = r["model"] == best
    write_metrics("url", rows)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": fitted[best], "name": best, "feature_names": FEATURE_NAMES, "dataset": dataset_name,
                 "metrics": [r for r in rows if r["model"] == best][0]}, MODEL_DIR / "url_model.joblib", compress=3)
    imp = getattr(fitted[best], "feature_importances_", None)
    if imp is not None:
        pd.DataFrame({"feature": FEATURE_NAMES, "importance": imp}).sort_values("importance", ascending=False).to_csv(
            RESULTS_DIR / "url_feature_importance.csv", index=False)
    print(f"Selected {best} -> {MODEL_DIR / 'url_model.joblib'}")


if __name__ == "__main__":
    main()
