"""C5 evidence: India-localized test set - detection with vs without localized rules.

    python evaluation/india_eval.py
'Detected' = email module score < 60 (HIGH or CRITICAL).  Also reports the ML model alone (p >= 0.5).
Outputs: results/india_testset_results.csv, results/india_testset_per_message.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from modules.email_analyzer import analyze_email  # noqa: E402
from utils.common import RESULTS_DIR  # noqa: E402

HERE = Path(__file__).resolve().parent


def main():
    df = pd.read_csv(HERE / "india_testset.csv")
    rows = []
    for _, r in df.iterrows():
        with_in = analyze_email(r.text, use_india_rules=True, explain=False)
        without = analyze_email(r.text, use_india_rules=False, explain=False)
        rules_only_in = analyze_email(r.text, use_india_rules=True, use_ml=False, explain=False)
        rules_only_out = analyze_email(r.text, use_india_rules=False, use_ml=False, explain=False)
        rows.append({"id": r.id, "category": r.category, "label": r.label,
                     "score_with_india_rules": round(with_in["score"], 1),
                     "score_without_india_rules": round(without["score"], 1),
                     "rules_only_with_india_rules": round(rules_only_in["score"], 1),
                     "rules_only_without_india_rules": round(rules_only_out["score"], 1),
                     "ml_probability": round(with_in["ml"]["probability"], 3),
                     "india_findings": ";".join(f["id"] for f in with_in["findings"] if f["id"].startswith("EMAIL_IN_")) or "-"})
    per = pd.DataFrame(rows)
    per.to_csv(RESULTS_DIR / "india_testset_per_message.csv", index=False)
    scam, legit = per[per.label == 1], per[per.label == 0]
    det = lambda s: round(float((s < 60).mean()), 4)
    summary = pd.DataFrame([
        {"configuration": "Hybrid WITH India rules (rules + ML)", "detection_rate_scams": det(scam.score_with_india_rules),
         "false_positive_rate_legit": det(legit.score_with_india_rules)},
        {"configuration": "Hybrid WITHOUT India rules (rules + ML)", "detection_rate_scams": det(scam.score_without_india_rules),
         "false_positive_rate_legit": det(legit.score_without_india_rules)},
        {"configuration": "Rules only WITH India rules", "detection_rate_scams": det(scam.rules_only_with_india_rules),
         "false_positive_rate_legit": det(legit.rules_only_with_india_rules)},
        {"configuration": "Rules only WITHOUT India rules", "detection_rate_scams": det(scam.rules_only_without_india_rules),
         "false_positive_rate_legit": det(legit.rules_only_without_india_rules)},
        {"configuration": "ML only (p >= 0.5)", "detection_rate_scams": round(float((scam.ml_probability >= 0.5).mean()), 4),
         "false_positive_rate_legit": round(float((legit.ml_probability >= 0.5).mean()), 4)},
    ])
    summary.insert(1, "n_scams", len(scam))
    summary.insert(2, "n_legit", len(legit))
    summary.to_csv(RESULTS_DIR / "india_testset_results.csv", index=False)
    print(per.to_string(index=False))
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
