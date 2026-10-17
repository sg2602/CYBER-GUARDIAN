"""C4 evidence: how often do rules and ML disagree, and does the UNCERTAIN flag point at real errors?

    python evaluation/disagreement_stats.py [--n_url 3000]
Runs the hybrid URL and email modules on held-out test splits.
'Flagged' = hybrid module score < 60 (HIGH or CRITICAL).
Outputs: results/disagreement_stats.csv, results/disagreement_cases.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from modules.email_analyzer import analyze_email  # noqa: E402
from modules.url_scanner import scan_url  # noqa: E402
from utils.common import DATA_DIR, RESULTS_DIR  # noqa: E402


def stats(name, df):
    y = df.label.astype(bool)
    hyb_wrong = (df.score < 60) != y
    rule_flag = df.rule_score < 60
    ml_flag = df.ml_prob >= 0.5
    unc = df.uncertain.astype(bool)
    n, nu = len(df), int(unc.sum())
    return {
        "module": name, "n": n,
        "disagreement_rate": round(nu / n, 4),
        "n_uncertain": nu,
        "rules_correct_when_uncertain": round(float((rule_flag[unc] == y[unc]).mean()), 4) if nu else None,
        "ml_correct_when_uncertain": round(float((ml_flag[unc] == y[unc]).mean()), 4) if nu else None,
        "hybrid_error_rate_uncertain": round(float(hyb_wrong[unc].mean()), 4) if nu else None,
        "hybrid_error_rate_certain": round(float(hyb_wrong[~unc].mean()), 4),
        "share_of_all_hybrid_errors_flagged_uncertain": round(float((hyb_wrong & unc).sum() / max(hyb_wrong.sum(), 1)), 4),
        "hybrid_error_rate_overall": round(float(hyb_wrong.mean()), 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_url", type=int, default=3000)
    ap.add_argument("--n_email", type=int, default=0, help="0 = whole email test split")
    args = ap.parse_args()
    out = []
    t = pd.read_csv(DATA_DIR / "url_test_split.csv").sample(args.n_url, random_state=11)
    rows = []
    for u, lab in zip(t.url.astype(str), t.label):
        r = scan_url(u, explain=False)
        rows.append({"label": lab, "score": r["score"], "rule_score": r["extra"]["rule_score"],
                     "ml_prob": r["ml"]["probability"], "uncertain": r["uncertain"]})
    du = pd.DataFrame(rows)
    out.append(stats("url", du))
    e = pd.read_csv(DATA_DIR / "email_test_split.csv")
    if args.n_email:
        e = e.sample(args.n_email, random_state=11)
    rows = []
    for txt, lab in zip(e.text.astype(str), e.label):
        r = analyze_email(txt, explain=False)
        rows.append({"label": lab, "score": r["score"], "rule_score": r["extra"]["rule_score"],
                     "ml_prob": r["ml"]["probability"], "uncertain": r["uncertain"]})
    de = pd.DataFrame(rows)
    out.append(stats("email", de))
    df = pd.DataFrame(out)
    df.to_csv(RESULTS_DIR / "disagreement_stats.csv", index=False)
    pd.concat([du.assign(module="url"), de.assign(module="email")])[lambda d: d.uncertain].to_csv(
        RESULTS_DIR / "disagreement_cases.csv", index=False)  # scores only - no raw URLs or email text
    print(df.T.to_string())


if __name__ == "__main__":
    main()
