"""Risk Assessment Engine - weighting, correlation penalties, critical floor,
coverage confidence (C4) and score traceability (C3).

Pipeline: module scores (0-100) -> weights renormalised over assessed modules ->
weighted score -> minus correlation penalties -> critical floor -> Cyber Safety Score.

Traceability invariant (unit-tested):
    final_score == 100 - sum(item["points"] for item in breakdown)
"""
from __future__ import annotations

from risk.chain_rules import CRITICAL_FLOOR, ESCALATION_FACTOR, HIGH_CHAIN_FLOOR
from risk.correlation_engine import correlate
from utils.common import MODULE_LABELS, MODULES, risk_level

WEIGHTS = {"password": 0.20, "email": 0.25, "url": 0.25, "permission": 0.15, "device": 0.15}
PARTIAL_COVERAGE_THRESHOLD = 0.6


def assessed_modules(results: dict) -> list[str]:
    return [m for m in MODULES if results.get(m) and results[m].get("assessed")]


def renormalized_weights(results: dict, weights: dict | None = None) -> dict[str, float]:
    weights = weights or WEIGHTS
    mods = assessed_modules(results)
    tot = sum(weights[m] for m in mods)
    return {m: weights[m] / tot for m in mods} if tot else {}


def baseline_score(results: dict, weights: dict | None = None) -> float | None:
    """Plain weighted average of module scores - no correlation, no floor (used for the scenario study)."""
    w = renormalized_weights(results, weights)
    if not w:
        return None
    return sum(w[m] * results[m]["score"] for m in w)


def coverage(results: dict) -> dict:
    n = len(assessed_modules(results))
    frac = n / len(MODULES)
    return {"assessed": n, "total": len(MODULES), "fraction": frac,
            "label": f"based on {n} of {len(MODULES)} modules (coverage {frac:.0%})",
            "partial": frac < PARTIAL_COVERAGE_THRESHOLD}


def _source_tag(f: dict) -> str:
    return {"rule": "rules", "ml": "ML/SHAP", "correlation": "correlation engine"}[f["source"]]


def score(results: dict, weights: dict | None = None, use_correlation: bool = True,
          escalation_factor: float = ESCALATION_FACTOR, critical_floor: float = CRITICAL_FLOOR,
          high_chain_floor: float | None = HIGH_CHAIN_FLOOR) -> dict:
    w = renormalized_weights(results, weights)
    cov = coverage(results)
    if not w:
        return {"score": None, "risk_level": None, "baseline": None, "coverage": cov, "weights": {}, "chains": [],
                "correlation_findings": [], "breakdown": [], "critical_findings": [], "floor_applied": False,
                "effective_module_scores": {}}
    base = sum(w[m] * results[m]["score"] for m in w)
    corr = correlate(results, w, escalation_factor=escalation_factor) if use_correlation else \
        {"chains": [], "findings": [], "effective_scores": {m: results[m]["score"] for m in w}}
    cfind = corr["findings"]
    # never let penalties push the score below 0 (shrink the last correlation finding if needed)
    total_corr = sum(f["points_lost"] for f in cfind)
    if base - total_corr < 0 and cfind:
        excess = total_corr - base
        for f in reversed(cfind):
            cut = min(excess, f["points_lost"])
            f["points_lost"] -= cut
            excess -= cut
            if excess <= 0:
                break
        total_corr = sum(f["points_lost"] for f in cfind)
    pre_floor = base - total_corr

    breakdown = []
    for m in w:
        for f in results[m]["findings"]:
            pts = w[m] * f["points_lost"]
            if pts <= 0:
                continue
            breakdown.append({"label": f"{MODULE_LABELS[m].split()[0]}: {f['title']}", "module": m,
                              "finding_id": f["id"], "source": f["source"], "severity": f["severity"],
                              "points": pts, "tag": _source_tag(f)})
    for f in cfind:
        if f["points_lost"] > 0:
            breakdown.append({"label": f"{f['title']}", "module": "correlation", "finding_id": f["id"],
                              "source": "correlation", "severity": f["severity"], "points": f["points_lost"],
                              "tag": "correlation engine"})

    all_findings = [f for m in w for f in results[m]["findings"]] + cfind
    has_critical = any(f["severity"] == "CRITICAL" for f in all_findings) if use_correlation else False
    final = pre_floor
    floor_applied = False
    high_chain = any(f["severity"] == "HIGH" for f in cfind)
    if high_chain and high_chain_floor is not None and final > high_chain_floor:
        breakdown.append({"label": f"High-severity attack-chain cap (score capped at {high_chain_floor:.0f})",
                          "module": "correlation", "finding_id": "HIGH_CHAIN_FLOOR", "source": "correlation",
                          "severity": "HIGH", "points": final - high_chain_floor, "tag": "correlation engine"})
        final = high_chain_floor
        floor_applied = True
    if has_critical and final > critical_floor:
        breakdown.append({"label": f"Critical-severity floor (score capped at {critical_floor:.0f})", "module": "correlation",
                          "finding_id": "CRITICAL_FLOOR", "source": "correlation", "severity": "CRITICAL",
                          "points": final - critical_floor, "tag": "correlation engine"})
        final = critical_floor
        floor_applied = True
    breakdown.sort(key=lambda b: -b["points"])
    critical = sorted([dict(f) for f in all_findings if f["severity"] in ("CRITICAL", "HIGH")],
                      key=lambda f: (f["severity"] != "CRITICAL", -f["points_lost"]))
    return {
        "score": final, "risk_level": risk_level(final), "baseline": base, "baseline_risk_level": risk_level(base),
        "coverage": cov, "weights": w, "chains": corr["chains"], "correlation_findings": cfind,
        "breakdown": breakdown, "critical_findings": critical, "floor_applied": floor_applied,
        "pre_floor": pre_floor, "effective_module_scores": corr["effective_scores"],
    }


def breakdown_text(s: dict, top: int = 12) -> str:
    if s["score"] is None:
        return "Not yet assessed"
    lines = [f"Cyber Safety Score {s['score']:.0f} = 100"]
    for b in s["breakdown"][:top]:
        lines.append(f"  − {b['points']:5.1f}  {b['label']} ({b['tag']})")
    rest = s["breakdown"][top:]
    if rest:
        lines.append(f"  − {sum(b['points'] for b in rest):5.1f}  {len(rest)} smaller findings")
    return "\n".join(lines)
