"""C1 - Threat Correlation Engine.

Runs after the five modules and before final scoring.  Detects cross-module
attack chains (data-driven rules in chain_rules.py), escalates compound risk by
adding correlation findings, and applies module tier effects.  The critical
floor itself is applied by the risk engine.
"""
from __future__ import annotations

import fnmatch

from risk.chain_rules import CHAIN_RULES, ESCALATION_FACTOR
from utils.common import TIER_MAX_SCORE, TIERS, make_finding, risk_level


def _index(results: dict) -> dict[str, list[tuple[str, dict]]]:
    idx = {}
    for m, r in results.items():
        if r and r.get("assessed"):
            for f in r["findings"]:
                idx.setdefault(f["id"], []).append((m, f))
    return idx


def evaluate(cond: dict, results: dict, idx: dict) -> tuple[bool, list[tuple[str, dict]]]:
    """Return (satisfied, participating findings)."""
    if "finding" in cond:
        pat = cond["finding"]
        hits = [mf for fid, lst in idx.items() if fnmatch.fnmatchcase(fid, pat) for mf in lst]
        return bool(hits), hits
    if "module_max" in cond:
        m, mx = cond["module_max"]
        r = results.get(m)
        ok = bool(r and r.get("assessed") and r["score"] is not None and r["score"] <= mx)
        return ok, []
    if "all" in cond:
        parts = []
        for c in cond["all"]:
            ok, p = evaluate(c, results, idx)
            if not ok:
                return False, []
            parts += p
        return True, parts
    if "any" in cond or "at_least" in cond:
        subs = cond.get("any") or cond["of"]
        need = 1 if "any" in cond else cond["at_least"]
        parts, n = [], 0
        for c in subs:
            ok, p = evaluate(c, results, idx)
            if ok:
                n += 1
                parts += p
        return (n >= need), (parts if n >= need else [])
    raise ValueError(f"Bad condition: {cond}")


def _dedupe(parts):
    seen, out = set(), []
    for m, f in parts:
        key = (m, f["id"])
        if key not in seen:
            seen.add(key)
            out.append((m, f))
    return out


def correlate(results: dict, weights: dict[str, float], rules: list[dict] | None = None,
              escalation_factor: float = ESCALATION_FACTOR) -> dict:
    """weights: renormalised module weights (sum to 1 over assessed modules).

    Correlation finding points are expressed directly in Cyber-Safety-Score
    units: escalation_factor x sum(weight_m x points_lost) over the participating
    findings, or - for tier effects - at least the amount needed to cap the
    module at the target tier (weighted).
    """
    rules = CHAIN_RULES if rules is None else rules
    idx = _index(results)
    eff = {m: r["score"] for m, r in results.items() if r and r.get("assessed")}
    chains, findings = [], []
    for rule in rules:
        ok, parts = evaluate(rule["condition"], results, idx)
        if not ok:
            continue
        parts = _dedupe(parts)
        weighted = sum(weights.get(m, 0.0) * f["points_lost"] for m, f in parts)
        points = escalation_factor * weighted
        eff_note = ""
        severity = rule["severity"]
        effect = rule["effect"]
        target = None
        if effect["type"] == "module_tier":
            target = effect["module"]
            if target in eff:
                cur = eff[target]
                if "tier" in effect:
                    cap = TIER_MAX_SCORE[effect["tier"]]
                else:
                    t = min(TIERS.index(risk_level(cur)) + effect.get("raise", 1), len(TIERS) - 1)
                    cap = TIER_MAX_SCORE[TIERS[t]]
                if cur > cap:
                    points = max(points, weights.get(target, 0.0) * (cur - cap))
                    eff[target] = cap
                new_tier = risk_level(min(cur, cap))
                eff_note = f"; {target} module escalated to {new_tier}"
                # Raising a module "+1 tier" from (or into) CRITICAL cannot be expressed at module level any more:
                # the chain itself becomes CRITICAL, which triggers the critical floor.
                if "raise" in effect and new_tier == "CRITICAL":
                    severity = "CRITICAL"
        participants = [f"{f['id']}" for _, f in parts]
        cf = make_finding(rule["id"], "correlation", f"Attack chain: {rule['name']}", severity, points,
                          f"Chain of {len(participants)} findings ({', '.join(participants)}); escalation "
                          f"{escalation_factor:.0%} of their weighted deficit {weighted:.1f}{eff_note}",
                          source="correlation", attack_ids=rule["attack_ids"], remediation_ids=rule["breaks_with"])
        cf["participants"] = participants
        cf["target_module"] = target
        findings.append(cf)
        chains.append({"id": rule["id"], "name": rule["name"], "severity": severity,
                       "attack_ids": rule["attack_ids"], "steps": rule["steps"], "explanation": rule["explanation"],
                       "participants": participants, "points": points, "target_module": target,
                       "breaks_with": rule["breaks_with"]})
    return {"chains": chains, "findings": findings, "effective_scores": eff}
