"""Run the module test-case suites (evaluation/test_suites/*.csv) and record real results.

    python evaluation/run_test_suites.py
Output: results/test_cases.csv  (Test ID, Module, Input (sanitized), Expected, Actual, Pass/Fail, Issue, Fixed?)
Expected tiers were written before running; failures are recorded, not hidden.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from modules.device_audit import QUESTIONS, audit_device  # noqa: E402
from modules.email_analyzer import analyze_email  # noqa: E402
from modules.password_audit import audit_password  # noqa: E402
from modules.permission_audit import audit_permissions  # noqa: E402
from modules.url_scanner import scan_url  # noqa: E402
from utils.common import RESULTS_DIR  # noqa: E402
from utils.feature_extraction import parse  # noqa: E402

SUITES = Path(__file__).resolve().parent / "test_suites"

# Explanations for known failures (written after inspecting them; expectations were NOT changed to make tests pass)
KNOWN_ISSUES = {
    "PW25": "Reverse digit run is detected as a sequence but not in the 10k list; scores HIGH, not CRITICAL",
    "E07": "ML (trained on long Western emails) gives a short promo email p~0.7; rules say LOW -> flagged UNCERTAIN",
    "E25": "ML misses the customs scam (p~0.26); rules + embedded URL say CRITICAL; fused score MODERATE, flagged UNCERTAIN",
    "U11": "Lexical ML false positive on a legit deep link (non allow-listed domain); flagged UNCERTAIN",
    "U12": "Lexical ML false positive on a legit deep link (non allow-listed domain); flagged UNCERTAIN",
    "U15": "Allow-listed domain but ML p~0.9 -> damped deficit still 27 points",
    "P09": "By design module tier comes from points (one CRITICAL permission = 25 pts); overall score IS capped CRITICAL via CH_BANKING_TROJAN",
    "P13": "By design module tier comes from points; the CRITICAL finding still caps the overall score at 39 (critical floor)",
}


def row(tid, module, inp, expected, res, note=""):
    ok = res["risk_level"] in expected.split("|")
    issue = "" if ok else KNOWN_ISSUES.get(tid, f"Got {res['risk_level']} (score {res['score']:.0f})")
    return {"Test ID": tid, "Module": module, "Input (sanitized)": inp, "Expected": expected,
            "Actual": f"{res['risk_level']} ({res['score']:.0f})", "Pass/Fail": "Pass" if ok else "Fail",
            "Issue": issue, "Fixed?": "" if ok else ("Working as designed" if tid in ("P09", "P13") else "No - documented limitation")}


def main():
    out = []
    for _, r in pd.read_csv(SUITES / "password.csv", dtype=str, keep_default_na=False).iterrows():
        res = audit_password(r.input, reused=r.reused == "1")
        out.append(row(r.test_id, "password", f"[{len(r.input)} chars] {r.note}" + (" (reused)" if r.reused == "1" else ""),
                       r.expected, res))
    for _, r in pd.read_csv(SUITES / "email.csv", dtype=str, keep_default_na=False).iterrows():
        res = analyze_email(r.input.replace("\\n", "\n"), explain=False)
        subj = next((ln[9:] for ln in r.input.split("\\n") if ln.startswith("Subject: ")), r.input[:40] + "...")
        out.append(row(r.test_id, "email", f"[{r.type}] {subj}", r.expected, res))
    for _, r in pd.read_csv(SUITES / "url.csv", dtype=str, keep_default_na=False).iterrows():
        res = scan_url(r.input, explain=False)
        out.append(row(r.test_id, "url", f"{parse(r.input)['registered_domain']} ({r.note})", r.expected, res))
    for _, r in pd.read_csv(SUITES / "permission.csv", dtype=str, keep_default_na=False).iterrows():
        res = audit_permissions(r.category, r.permissions.split(";"))
        out.append(row(r.test_id, "permission", f"{r.category}: {r.permissions.replace(';', ', ')}", r.expected, res))
    for _, r in pd.read_csv(SUITES / "device.csv", dtype=str, keep_default_na=False).iterrows():
        ans = {k: "YES" for k in QUESTIONS}
        for k in filter(None, r.no_answers.split(";")):
            ans[k] = "NO"
        for k in filter(None, r.unsure_answers.split(";")):
            ans[k] = "NOT_SURE"
        res = audit_device(ans)
        out.append(row(r.test_id, "device", f"NO: {r.no_answers or '-'}; NOT SURE: {r.unsure_answers or '-'}",
                       r.expected, res))
    df = pd.DataFrame(out)
    df.to_csv(RESULTS_DIR / "test_cases.csv", index=False)
    summ = df.groupby("Module")["Pass/Fail"].apply(lambda s: f"{(s == 'Pass').sum()}/{len(s)}")
    print(summ.to_string())
    print(f"TOTAL {(df['Pass/Fail'] == 'Pass').sum()}/{len(df)}")
    print(df[df["Pass/Fail"] == "Fail"][["Test ID", "Input (sanitized)", "Expected", "Actual"]].to_string(index=False))


if __name__ == "__main__":
    main()
