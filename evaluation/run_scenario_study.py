"""C1 evidence: plain weighted average vs Threat Correlation Engine on 13 user profiles.

    python evaluation/run_scenario_study.py
Outputs: results/scenario_study.csv, results/scenario_study.png, results/scenario_study_summary.txt
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from modules.device_audit import audit_device  # noqa: E402
from modules.email_analyzer import analyze_email  # noqa: E402
from modules.password_audit import audit_password  # noqa: E402
from modules.permission_audit import audit_permissions  # noqa: E402
from modules.url_scanner import scan_url  # noqa: E402
from risk.risk_engine import score  # noqa: E402
from utils.common import RESULTS_DIR, TIER_COLORS, TIERS, risk_level  # noqa: E402

PROFILES = Path(__file__).resolve().parent / "scenario_profiles.json"


def build_results(p: dict, device_good: dict) -> dict:
    res = {}
    if p.get("password"):
        res["password"] = audit_password(p["password"]["password"], reused=p["password"].get("reused", False))
    if p.get("email"):
        res["email"] = analyze_email(p["email"]["raw"], explain=False)
    if p.get("url"):
        res["url"] = scan_url(p["url"]["url"], explain=False)
    if p.get("permission"):
        res["permission"] = audit_permissions(p["permission"]["category"], p["permission"]["permissions"])
    if p.get("device"):
        ans = dict(device_good)
        if isinstance(p["device"], dict):
            ans.update(p["device"])
        res["device"] = audit_device(ans)
    from risk.assessment import normalise_results
    return normalise_results(res)


def main():
    data = json.loads(PROFILES.read_text())
    rows = []
    for p in data["profiles"]:
        res = build_results(p, data["device_good"])
        s = score(res)
        s_nohf = score(res, high_chain_floor=None)  # ablation: module-tier effects only, no HIGH-chain cap
        base_t, corr_t, exp = risk_level(s["baseline"]), s["risk_level"], p["expected"]
        dangerous = exp in ("HIGH", "CRITICAL")
        rows.append({
            "profile": p["id"], "name": p["name"], "expected": exp,
            "baseline_score": round(s["baseline"], 1), "baseline_tier": base_t,
            "correlated_score": round(s["score"], 1), "correlated_tier": corr_t,
            "chains": ";".join(c["id"] for c in s["chains"]) or "-",
            "ablation_no_high_cap_score": round(s_nohf["score"], 1), "ablation_no_high_cap_tier": s_nohf["risk_level"],
            "coverage": f"{s['coverage']['assessed']}/5",
            "baseline_correct": base_t == exp, "correlated_correct": corr_t == exp,
            "dangerous": dangerous,
            "baseline_mislabels_danger": dangerous and base_t in ("LOW", "MODERATE"),
            "correlated_mislabels_danger": dangerous and corr_t in ("LOW", "MODERATE"),
            "baseline_tier_error": abs(TIERS.index(base_t) - TIERS.index(exp)),
            "correlated_tier_error": abs(TIERS.index(corr_t) - TIERS.index(exp)),
        })
    df = pd.DataFrame(rows)
    RESULTS_DIR.mkdir(exist_ok=True)
    df.to_csv(RESULTS_DIR / "scenario_study.csv", index=False)
    n = len(df)
    nd = int(df.dangerous.sum())
    summary = (
        f"Scenario study ({n} profiles, expected tiers assigned a priori)\n"
        f"Exact tier agreement: baseline {int(df.baseline_correct.sum())}/{n}, correlated {int(df.correlated_correct.sum())}/{n}\n"
        f"Dangerous profiles (expected HIGH/CRITICAL): {nd}\n"
        f"  labelled LOW/MODERATE by plain average:      {int(df.baseline_mislabels_danger.sum())}/{nd}\n"
        f"  labelled LOW/MODERATE by correlation engine: {int(df.correlated_mislabels_danger.sum())}/{nd}\n"
        f"Ablation (correlation without HIGH-chain cap): exact {int((df.ablation_no_high_cap_tier == df.expected).sum())}/{n}, "
        f"dangerous mislabelled {int((df.dangerous & df.ablation_no_high_cap_tier.isin(['LOW', 'MODERATE'])).sum())}/{nd}\n"
        f"Mean absolute tier error: baseline {df.baseline_tier_error.mean():.2f}, correlated {df.correlated_tier_error.mean():.2f}\n"
    )
    (RESULTS_DIR / "scenario_study_summary.txt").write_text(summary)
    print(df[["profile", "expected", "baseline_score", "baseline_tier", "correlated_score", "correlated_tier", "ablation_no_high_cap_tier", "chains"]]
          .to_string(index=False))
    print(summary)

    fig, ax = plt.subplots(figsize=(11, 4.6), dpi=120)
    x = range(n)
    ax.bar([i - 0.2 for i in x], df.baseline_score, width=0.4, label="Plain weighted average", color="#9aa5b1")
    ax.bar([i + 0.2 for i in x], df.correlated_score, width=0.4, label="CyberGuardian (correlated)",
           color=[TIER_COLORS[t] for t in df.correlated_tier])
    for lo, hi, t in [(0, 40, "CRITICAL"), (40, 60, "HIGH"), (60, 80, "MODERATE"), (80, 100, "LOW")]:
        ax.axhspan(lo, hi, color=TIER_COLORS[t], alpha=0.08)
    for i, e in enumerate(df.expected):
        ax.text(i, 102, e[:4], ha="center", fontsize=7)
    ax.set_xticks(list(x), df.profile)
    ax.set_ylim(0, 108)
    ax.set_ylabel("Cyber Safety Score (higher = safer)")
    ax.set_title("Scenario study: plain average vs Threat Correlation Engine (text above = expected tier)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "scenario_study.png")


if __name__ == "__main__":
    main()
