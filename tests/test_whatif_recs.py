from conftest import device
from modules.email_analyzer import analyze_email
from modules.password_audit import audit_password
from risk.recommendation_engine import ACTIONS, EFFORT_WEIGHT, recommend
from risk.risk_engine import score
from risk.whatif_simulator import apply_actions, optimize_budget, rank_actions, simulate, top_k_projection
from utils import demo_inputs as d


def takeover():
    return {"password": audit_password("Samriddhi123"), "email": analyze_email(d.DEMO_EMAIL), "device": device(mfa="NO")}


def test_mfa_breaks_account_takeover():
    res = takeover()
    cur = score(res)
    rows = {r["action_id"]: r for r in rank_actions(res, cur)}
    assert "CH_ACCOUNT_TAKEOVER" in rows["ACT_ENABLE_MFA"]["breaks_chains"]
    assert rows["ACT_ENABLE_MFA"]["gain"] > 0
    assert "CH_ACCOUNT_TAKEOVER" not in {c["id"] for c in simulate(res, ["ACT_ENABLE_MFA"])["chains"]}


def test_gains_non_negative_and_ranked(demo_results):
    cur = score(demo_results)
    rows = rank_actions(demo_results, cur)
    assert rows and all(r["gain"] >= -1e-9 for r in rows)
    ratios = [r["gain_per_effort"] for r in rows]
    assert ratios == sorted(ratios, reverse=True)
    assert abs(rows[0]["new_score"] - cur["score"] - rows[0]["gain"]) < 1e-9


def test_top3_projection_not_worse(demo_results):
    cur = score(demo_results)
    t3 = top_k_projection(demo_results, rank_actions(demo_results, cur), 3)
    assert len(t3["actions"]) == 3 and t3["projected_score"] >= cur["score"]


def test_apply_actions_does_not_mutate(demo_results):
    before = demo_results["password"]["score"]
    new = apply_actions(demo_results, ["ACT_LONG_PASSWORD"])
    assert demo_results["password"]["score"] == before
    assert new["password"]["score"] == 100


def test_recommendations_specific_and_prioritised(demo_results):
    s = score(demo_results)
    recs = recommend(demo_results, s)
    by = {r["action_id"]: r for r in recs}
    assert by["ACT_ENABLE_MFA"]["priority"] == "Immediate"
    assert any("1930" in x for x in by["ACT_REPORT_INDIA_SCAM"]["steps"])
    assert any("UPI PIN" in x for x in by["ACT_REPORT_INDIA_SCAM"]["steps"])
    for r in recs:
        assert r["action_id"] in ACTIONS and r["effort"] in ("Low", "Medium", "High")


def test_optimize_budget_respects_constraints(demo_results):
    cur = score(demo_results)
    for b in (1, 2, 3, 5):
        opt = optimize_budget(demo_results, max_effort=b, current=cur)
        assert opt["total_effort"] <= b
        calculated_effort = sum(EFFORT_WEIGHT[ACTIONS[a]["effort"]] for a in opt["actions"])
        assert calculated_effort == opt["total_effort"]
        assert opt["gain"] >= -1e-9
        assert opt["projected_score"] >= cur["score"] - 1e-9
        assert len(opt["action_details"]) == len(opt["actions"])


def test_optimize_budget_monotonicity(demo_results):
    opt1 = optimize_budget(demo_results, max_effort=1)
    opt2 = optimize_budget(demo_results, max_effort=2)
    opt3 = optimize_budget(demo_results, max_effort=3)
    assert opt1["gain"] <= opt2["gain"] + 1e-9
    assert opt2["gain"] <= opt3["gain"] + 1e-9


def test_optimize_budget_breaks_attack_chains(demo_results):
    cur = score(demo_results)
    cur_chains = {c["id"] for c in cur["chains"]}
    assert len(cur_chains) > 0
    opt = optimize_budget(demo_results, max_effort=3, current=cur)
    assert len(opt["broken_chains"]) > 0
    for ch in opt["broken_chains"]:
        assert ch in cur_chains
        assert ch not in opt["remaining_chains"]


def test_optimize_budget_zero_or_empty(demo_results):
    opt_zero = optimize_budget(demo_results, max_effort=0)
    assert opt_zero["actions"] == []
    assert opt_zero["total_effort"] == 0
    assert opt_zero["gain"] == 0.0

    opt_empty = optimize_budget({}, max_effort=2)
    assert opt_empty["actions"] == []
    assert opt_empty["total_effort"] == 0
