"""Metric helpers shared by both training scripts (real numbers only - computed from predictions)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score  # noqa: E402

from utils.common import RESULTS_DIR  # noqa: E402

METRICS_CSV = RESULTS_DIR / "ml_metrics.csv"


def evaluate(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def save_confusion(y_true, y_pred, path: Path, title: str, labels=("Negative", "Positive")):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(4.2, 3.6), dpi=120)
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=11)
    ax.set_xticks([0, 1], labels=[f"Pred {labels[0]}", f"Pred {labels[1]}"], fontsize=8)
    ax.set_yticks([0, 1], labels=[f"True {labels[0]}", f"True {labels[1]}"], fontsize=8)
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)


def write_metrics(task: str, rows: list[dict]):
    cols = ["task", "model", "dataset", "n_train", "n_test", "accuracy", "precision", "recall", "f1",
            "tn", "fp", "fn", "tp", "selected", "train_seconds"]
    new = pd.DataFrame(rows)[cols]
    if METRICS_CSV.exists():
        old = pd.read_csv(METRICS_CSV)
        old = old[old.task != task]
        new = pd.concat([old, new], ignore_index=True)
    METRICS_CSV.parent.mkdir(parents=True, exist_ok=True)
    new.sort_values(["task", "model"]).to_csv(METRICS_CSV, index=False)
