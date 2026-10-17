"""End-to-end orchestration: ModuleResults -> correlation -> risk -> recommendations -> What-If."""
from __future__ import annotations

import uuid
from datetime import datetime

from risk.recommendation_engine import recommend
from risk.risk_engine import score
from risk.whatif_simulator import optimize_budget, rank_actions, top_k_projection
from utils.common import MODULES, skipped_result


def normalise_results(results: dict) -> dict:
    return {m: (results.get(m) or skipped_result(m)) for m in MODULES}


def run_assessment(results: dict, with_whatif: bool = True) -> dict:
    results = normalise_results(results)
    s = score(results)
    recs = recommend(results, s) if s["score"] is not None else []
    ranked = rank_actions(results, s) if (with_whatif and s["score"] is not None) else []
    return {
        "assessment_id": "CG-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6].upper(),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "modules": results,
        **s,
        "uncertain_modules": [m for m in MODULES if results[m].get("uncertain")],
        "recommendations": recs,
        "whatif": ranked,
        "whatif_top3": top_k_projection(results, ranked, 3) if ranked else None,
        "whatif_budget": optimize_budget(results, max_effort=2, current=s) if (with_whatif and s["score"] is not None) else None,
    }
