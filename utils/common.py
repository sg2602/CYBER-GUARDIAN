"""Shared data contract (Finding / ModuleResult), risk bands and helpers.

Every module returns a ModuleResult built with :func:`make_module_result` so that
all downstream engines (correlation, risk, recommendation, what-if, report, DB)
can rely on exactly the same structure.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR = ROOT / "utils" / "wordlists"
MODEL_DIR = ROOT / "ml" / "models"
RESULTS_DIR = ROOT / "results"
DATA_DIR = ROOT / "data"

MODULES = ["password", "email", "url", "permission", "device"]
MODULE_LABELS = {
    "password": "Password Security",
    "email": "Email Security",
    "url": "Website/URL Security",
    "permission": "App Permission Risk",
    "device": "Device Security",
    "correlation": "Threat Correlation",
}

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Risk tiers, best -> worst.  Bands are used everywhere in the project.
TIERS = ["LOW", "MODERATE", "HIGH", "CRITICAL"]
TIER_LABELS = {"LOW": "LOW RISK", "MODERATE": "MODERATE", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
# Upper bound (inclusive) of the score range for each tier.
TIER_MAX_SCORE = {"LOW": 100.0, "MODERATE": 79.0, "HIGH": 59.0, "CRITICAL": 39.0}
TIER_COLORS = {"LOW": "#10B981", "MODERATE": "#F59E0B", "HIGH": "#F97316", "CRITICAL": "#EF4444"}


def risk_level(score: float) -> str:
    """80-100 LOW, 60-79 MODERATE, 40-59 HIGH, 0-39 CRITICAL (higher score = safer)."""
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MODERATE"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"


def tier_index(tier: str) -> int:
    return TIERS.index(tier)


def make_finding(fid: str, module: str, title: str, severity: str, points_lost: float,
                 evidence: str, source: str = "rule", attack_ids: Iterable[str] = (),
                 remediation_ids: Iterable[str] = ()) -> dict:
    assert severity in SEVERITY_RANK, severity
    assert source in ("rule", "ml", "correlation"), source
    return {
        "id": fid,
        "module": module,
        "title": title,
        "severity": severity,
        "points_lost": float(points_lost),
        "evidence": evidence,
        "source": source,
        "attack_ids": list(attack_ids),
        "remediation_ids": list(remediation_ids),
    }


def make_module_result(module: str, findings: list[dict], ml: dict | None = None,
                       rule_ml_agreement: bool | None = None, uncertain: bool = False,
                       explanations: list[str] | None = None, assessed: bool = True,
                       extra: dict | None = None) -> dict:
    """Build a ModuleResult.  Module score = 100 - sum(points_lost).

    If the raw deficit exceeds 100, every finding's points are scaled down
    proportionally so that ``sum(points_lost) == 100 - score`` always holds
    exactly.  This invariant is what makes score traceability (C3) reconcile.
    """
    findings = [dict(f) for f in findings]
    raw = sum(f["points_lost"] for f in findings)
    if raw > 100:
        k = 100.0 / raw
        for f in findings:
            f["points_lost"] = f["points_lost"] * k
    deficit = sum(f["points_lost"] for f in findings)
    score = max(0.0, 100.0 - deficit)
    findings.sort(key=lambda f: (-f["points_lost"], f["id"]))
    res = {
        "module": module,
        "score": score,
        "risk_level": risk_level(score),
        "findings": findings,
        "ml": ml,
        "rule_ml_agreement": rule_ml_agreement,
        "uncertain": bool(uncertain),
        "explanations": explanations if explanations is not None else [f["title"] for f in findings],
        "assessed": assessed,
    }
    if extra:
        res["extra"] = extra
    return res


def skipped_result(module: str) -> dict:
    return {
        "module": module, "score": None, "risk_level": None, "findings": [], "ml": None,
        "rule_ml_agreement": None, "uncertain": False, "explanations": [], "assessed": False,
    }


def rescore(result: dict) -> dict:
    """Recompute score/risk level after findings were removed (used by What-If)."""
    if not result.get("assessed"):
        return result
    deficit = sum(f["points_lost"] for f in result["findings"])
    score = max(0.0, 100.0 - deficit)
    result["score"] = score
    result["risk_level"] = risk_level(score)
    return result


def rule_ml_disagree(rule_score: float, ml_score: float, min_gap: float = 20.0) -> bool:
    """C4 disagreement rule.

    Rules and ML 'disagree' when one places the input on the safe side
    (LOW/MODERATE, score >= 60) and the other on the risky side (HIGH/CRITICAL,
    score < 60) *and* their scores are at least ``min_gap`` points apart, i.e.
    they differ by at least one full risk tier.
    """
    safe_r, safe_m = rule_score >= 60, ml_score >= 60
    return (safe_r != safe_m) and abs(rule_score - ml_score) >= min_gap


def load_wordlist(name: str) -> list[str]:
    path = WORDLIST_DIR / name
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def levenshtein(a: str, b: str, max_dist: int | None = None) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > (max_dist if max_dist is not None else 10 ** 9):
        return (max_dist or 0) + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
