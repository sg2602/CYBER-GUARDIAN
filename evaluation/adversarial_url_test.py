"""Adversarial URL robustness: perturb malicious URLs and compare rules-only, ML-only and hybrid detection.

    python evaluation/adversarial_url_test.py [--n 300]
Uses phishing URLs from the held-out test split (data/url_test_split.csv).
'Detected (HIGH+)'     = score < 60  (rules-only rule score, ML-only 100*(1-p), hybrid module score)
'Flagged (MODERATE+)'  = score < 80
ML-only at p >= 0.5 is the classifier's own decision threshold (= ML score < 50).
Outputs: results/adversarial_url_results.csv, results/adversarial_url.png
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from ml.url_model import predict_proba_batch  # noqa: E402
from modules.url_scanner import rule_score, scan_url  # noqa: E402
from utils.common import DATA_DIR, RESULTS_DIR  # noqa: E402
from utils.feature_extraction import normalize_url, parse  # noqa: E402

SEED = 7
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}


def homoglyph(u, rng):
    p = parse(u)
    host = p["host"]
    reg = p["registered_domain"]
    core = reg.split(".")[0]
    idx = [i for i, ch in enumerate(core) if ch in HOMOGLYPHS]
    if not idx:
        return u
    i = rng.choice(idx)
    new_core = core[:i] + HOMOGLYPHS[core[i]] + core[i + 1:]
    return u.replace(host, host.replace(core, new_core, 1), 1)


def prepend_https(u, rng):
    return "https://" + normalize_url(u).split("://", 1)[1]


def shortener(u, rng):
    return "https://bit.ly/" + "".join(rng.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(7))


def long_benign_path(u, rng):
    u = normalize_url(u)
    return u.rstrip("/") + "/blog/2024/03/easy-weeknight-dinner-recipes-for-busy-families/index.html"


def subdomain_padding(u, rng):
    p = parse(u)
    if p["is_ip"]:
        return u
    return u.replace(p["host"], "www.secure.accounts.mail." + p["host"], 1)


PERTURBATIONS = {"original": lambda u, r: normalize_url(u), "homoglyph_swap": homoglyph, "prepend_https": prepend_https,
                 "url_shortener": shortener, "long_benign_path": long_benign_path, "subdomain_padding": subdomain_padding}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    args = ap.parse_args()
    test = pd.read_csv(DATA_DIR / "url_test_split.csv")
    mal = test[test.label == 1].sample(args.n, random_state=SEED).url.astype(str).tolist()
    rng = random.Random(SEED)
    rows = []
    for name, fn in PERTURBATIONS.items():
        urls = [fn(u, rng) for u in mal]
        rs = [rule_score(u) for u in urls]
        ms = [100 * (1 - p) for p in predict_proba_batch(urls)]
        hs = [scan_url(u, explain=False)["score"] for u in urls]
        n = len(urls)
        rate = lambda xs, t: round(sum(x < t for x in xs) / n, 4)
        rows.append({"perturbation": name, "n": n,
                     "rules_only": rate(rs, 60), "ml_only": rate(ms, 50), "hybrid": rate(hs, 60),
                     "rules_only_moderate+": rate(rs, 80), "ml_only_moderate+": rate(ms, 80),
                     "hybrid_moderate+": rate(hs, 80)})
        print(rows[-1])
    df = pd.DataFrame(rows)
    df.to_csv(RESULTS_DIR / "adversarial_url_results.csv", index=False)
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.2), dpi=120, sharey=True)
    x = range(len(df))
    for ax, suffix, title in [(axes[0], "", "Detected as HIGH+ (score < 60; ML p >= 0.5)"),
                              (axes[1], "_moderate+", "Flagged MODERATE+ (score < 80)")]:
        for k, (col, c) in enumerate([("rules_only", "#9aa5b1"), ("ml_only", "#1565c0"), ("hybrid", "#c62828")]):
            ax.bar([i + (k - 1) * 0.27 for i in x], df[col + suffix] * 100, width=0.27, label=col.replace("_", "-"), color=c)
        ax.set_xticks(list(x), df.perturbation, rotation=20, fontsize=8)
        ax.set_title(title, fontsize=10)
        ax.set_ylim(0, 105)
    axes[0].set_ylabel(f"Detection rate (%) - {args.n} held-out phishing URLs")
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "adversarial_url.png")


if __name__ == "__main__":
    main()
