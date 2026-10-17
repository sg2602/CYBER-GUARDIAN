"""C2 - What-If Remediation Simulator (counterfactual explanations).

For each available action: remove the findings it resolves, re-run the
correlation + risk engine, and record the new score.  Actions are ranked by
score gain / effort weight (Low=1, Medium=2, High=3).
"""
from __future__ import annotations

import copy

from risk.recommendation_engine import ACTIONS, EFFORT_WEIGHT, finding_resolved_by
from risk.risk_engine import score
from utils.common import rescore


def apply_actions(results: dict, action_ids: list[str]) -> dict:
    new = copy.deepcopy(results)
    for m, r in new.items():
        if not r or not r.get("assessed"):
            continue
        r["findings"] = [f for f in r["findings"] if not any(finding_resolved_by(a, f["id"]) for a in action_ids)]
        rescore(r)
    return new


def simulate(results: dict, action_ids: list[str]) -> dict:
    return score(apply_actions(results, action_ids))


def rank_actions(results: dict, current: dict | None = None, candidate_ids: list[str] | None = None) -> list[dict]:
    current = current or score(results)
    if current["score"] is None:
        return []
    present = {f["id"] for r in results.values() if r and r.get("assessed") for f in r["findings"]}
    if candidate_ids is None:
        candidate_ids = [a for a in ACTIONS if any(finding_resolved_by(a, fid) for fid in present)]
    cur_chains = {c["id"] for c in current["chains"]}
    rows = []
    for a in candidate_ids:
        s = simulate(results, [a])
        gain = s["score"] - current["score"]
        broken = sorted(cur_chains - {c["id"] for c in s["chains"]})
        rows.append({"action_id": a, "title": ACTIONS[a]["title"], "effort": ACTIONS[a]["effort"],
                     "new_score": s["score"], "new_risk_level": s["risk_level"], "gain": gain,
                     "gain_per_effort": gain / EFFORT_WEIGHT[ACTIONS[a]["effort"]], "breaks_chains": broken})
    rows.sort(key=lambda r: (-r["gain_per_effort"], -r["gain"], r["action_id"]))
    return rows


def top_k_projection(results: dict, ranked: list[dict], k: int = 3) -> dict:
    """Apply the top-k ranked actions together (joint effect, not the sum of individual gains)."""
    chosen = [r["action_id"] for r in ranked if r["gain"] > 0][:k]
    s = simulate(results, chosen) if chosen else score(results)
    return {"actions": chosen, "projected_score": s["score"], "projected_risk_level": s["risk_level"],
            "remaining_chains": [c["id"] for c in s["chains"]]}


def optimize_budget(
    results: dict,
    max_effort: int = 2,
    current: dict | None = None,
    candidate_ids: list[str] | None = None,
) -> dict:
    """Find the optimal action subset within a maximum effort budget that maximizes
    security score gain and breaks the most attack chains.

    Solves the non-linear knapsack problem using combinatorial counterfactual simulation.
    Effort weights: Low=1 (~15 min), Medium=2 (~30 min), High=3 (~60 min).
    """
    current = current or score(results)
    if current["score"] is None or max_effort <= 0:
        return {
            "actions": [],
            "total_effort": 0,
            "projected_score": current.get("score"),
            "projected_risk_level": current.get("risk_level", "UNKNOWN"),
            "gain": 0.0,
            "broken_chains": [],
            "remaining_chains": [c["id"] for c in current.get("chains", [])],
            "action_details": [],
        }

    present = {f["id"] for r in results.values() if r and r.get("assessed") for f in r["findings"]}
    if candidate_ids is None:
        candidate_ids = [a for a in ACTIONS if any(finding_resolved_by(a, fid) for fid in present)]

    ranked = rank_actions(results, current, candidate_ids)
    viable_candidates = [r["action_id"] for r in ranked if r["gain"] > 0][:10]
    if not viable_candidates:
        return {
            "actions": [],
            "total_effort": 0,
            "projected_score": current["score"],
            "projected_risk_level": current["risk_level"],
            "gain": 0.0,
            "broken_chains": [],
            "remaining_chains": [c["id"] for c in current["chains"]],
            "action_details": [],
        }

    items = [
        (a, EFFORT_WEIGHT[ACTIONS[a]["effort"]])
        for a in viable_candidates
        if EFFORT_WEIGHT[ACTIONS[a]["effort"]] <= max_effort
    ]
    if not items:
        return {
            "actions": [],
            "total_effort": 0,
            "projected_score": current["score"],
            "projected_risk_level": current["risk_level"],
            "gain": 0.0,
            "broken_chains": [],
            "remaining_chains": [c["id"] for c in current["chains"]],
            "action_details": [],
        }

    cur_chains = {c["id"] for c in current["chains"]}
    best_combo: list[str] = []
    best_sim: dict = current
    best_effort: int = 0
    best_broken: list[str] = []
    best_key = (0.0, 0, 0, 0)

    def search(idx: int, rem_effort: int, chosen: list[str]) -> None:
        nonlocal best_combo, best_sim, best_effort, best_broken, best_key
        if chosen:
            tot_w = sum(EFFORT_WEIGHT[ACTIONS[a]["effort"]] for a in chosen)
            sim = simulate(results, chosen)
            gain = sim["score"] - current["score"]
            broken = sorted(cur_chains - {c["id"] for c in sim["chains"]})
            key = (round(gain, 4), len(broken), -tot_w, -len(chosen))
            if key > best_key:
                best_key = key
                best_combo = list(chosen)
                best_sim = sim
                best_effort = tot_w
                best_broken = broken

        for i in range(idx, len(items)):
            aid, w = items[i]
            if w <= rem_effort:
                chosen.append(aid)
                search(i + 1, rem_effort - w, chosen)
                chosen.pop()

    search(0, max_effort, [])

    if not best_combo:
        return {
            "actions": [],
            "total_effort": 0,
            "projected_score": current["score"],
            "projected_risk_level": current["risk_level"],
            "gain": 0.0,
            "broken_chains": [],
            "remaining_chains": list(cur_chains),
            "action_details": [],
        }

    action_details = [
        {
            "action_id": a,
            "title": ACTIONS[a]["title"],
            "effort": ACTIONS[a]["effort"],
            "effort_weight": EFFORT_WEIGHT[ACTIONS[a]["effort"]],
            "steps": ACTIONS[a]["steps"],
        }
        for a in best_combo
    ]

    return {
        "actions": best_combo,
        "total_effort": best_effort,
        "projected_score": best_sim["score"],
        "projected_risk_level": best_sim["risk_level"],
        "gain": best_sim["score"] - current["score"],
        "broken_chains": best_broken,
        "remaining_chains": [c["id"] for c in best_sim["chains"]],
        "action_details": action_details,
    }
