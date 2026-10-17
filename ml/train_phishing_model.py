"""Train the phishing-email model: Logistic Regression vs Random Forest, pick best by F1.

    python ml/train_phishing_model.py
    python ml/train_phishing_model.py --data path/to/your.csv   (columns: text,label)

Outputs: ml/models/phishing_model.joblib, results/ml_metrics.csv (rows task=email),
results/confusion_email_<model>.png, data/email_test_split.csv.
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
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from ml.metrics_utils import evaluate, save_confusion, write_metrics  # noqa: E402
from ml.phishing_model import EmailFeaturizer  # noqa: E402
from utils.common import DATA_DIR, MODEL_DIR, RESULTS_DIR  # noqa: E402

SEED = 42


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DATA_DIR / "email_dataset.csv"))
    args = ap.parse_args()
    df = pd.read_csv(args.data).dropna(subset=["text"])
    dataset_name = Path(args.data).name
    if "source" in df.columns:
        dataset_name += " (" + " + ".join(sorted(df.source.unique())) + ")"
    y = df.label.astype(int).values
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=0.2, stratify=y, random_state=SEED)
    df.iloc[te].to_csv(DATA_DIR / "email_test_split.csv", index=False)
    texts = df.text.astype(str).values
    feat = EmailFeaturizer().fit(texts[tr])
    Xtr, Xte = feat.transform(texts[tr]), feat.transform(texts[te])
    print(f"{len(df)} emails, {Xtr.shape[1]} features")
    candidates = {
        "LogisticRegression": LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced"),
        "RandomForest": RandomForestClassifier(n_estimators=300, min_samples_leaf=1, n_jobs=-1,
                                               class_weight="balanced", random_state=SEED),
    }
    rows, fitted = [], {}
    for name, model in candidates.items():
        t = time.time()
        model.fit(Xtr, y[tr])
        pred = model.predict(Xte)
        m = evaluate(y[te], pred)
        m.update(task="email", model=name, dataset=dataset_name, n_train=len(tr), n_test=len(te),
                 train_seconds=round(time.time() - t, 1))
        rows.append(m)
        fitted[name] = model
        save_confusion(y[te], pred, RESULTS_DIR / f"confusion_email_{name}.png", f"Email model - {name}",
                       labels=["Legitimate", "Phishing"])
        print(f"{name}: acc={m['accuracy']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} f1={m['f1']:.4f}")
    best = max(rows, key=lambda r: r["f1"])["model"]
    for r in rows:
        r["selected"] = r["model"] == best
    write_metrics("email", rows)
    bg = np.asarray(Xtr.mean(axis=0)).ravel()
    joblib.dump({"model": fitted[best], "name": best, "featurizer": feat, "background_mean": bg,
                 "dataset": dataset_name, "metrics": [r for r in rows if r["model"] == best][0]},
                MODEL_DIR / "phishing_model.joblib")
    print(f"Selected {best} -> {MODEL_DIR / 'phishing_model.joblib'}")


if __name__ == "__main__":
    main()
