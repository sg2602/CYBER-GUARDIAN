import itertools
import random

import pytest

from conftest import device
from modules.password_audit import audit_password
from risk.risk_engine import WEIGHTS, baseline_score, coverage, renormalized_weights, score
from utils.common import risk_level, skipped_result


def test_risk_bands():
    assert [risk_level(x) for x in (100, 80, 79.9, 60, 59.9, 40, 39.9, 0)] == \
        ["LOW", "LOW", "MODERATE", "MODERATE", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def test_weights_sum_and_renormalisation():
    assert abs(sum(WEIGHTS.values()) - 1) < 1e-12
    res = {"password": audit_password("Samriddhi123"), "device": device(), "email": skipped_result("email")}
    w = renormalized_weights(res)
    assert set(w) == {"password", "device"}
    assert abs(sum(w.values()) - 1) < 1e-12
    assert abs(w["password"] - 0.20 / 0.35) < 1e-12
    assert abs(baseline_score(res) - (w["password"] * res["password"]["score"] + w["device"] * 100)) < 1e-9


def test_coverage():
    res = {"password": audit_password("Samriddhi123"), "device": device()}
    c = coverage(res)
    assert c["assessed"] == 2 and c["partial"] and "2 of 5" in c["label"]
    assert score({})["score"] is None


def _reconciles(s):
    return abs(100 - sum(b["points"] for b in s["breakdown"]) - s["score"]) < 1e-9


def test_breakdown_reconciles_demo(demo_results):
    assert _reconciles(score(demo_results))


def test_breakdown_reconciles_every_subset(demo_results, good_results):
    mods = list(demo_results)
    rng = random.Random(0)
    for k in range(1, 6):
        for combo in itertools.combinations(mods, k):
            res = {m: (demo_results[m] if rng.random() < 0.5 else good_results[m]) for m in combo}
            s = score(res)
            assert _reconciles(s), combo
            assert 0 <= s["score"] <= 100


@pytest.mark.parametrize("m", ["password", "email", "url", "permission", "device"])
def test_baseline_without_correlation_equals_weighted_average(demo_results, m):
    res = {m: demo_results[m]}
    assert abs(score(res, use_correlation=False)["score"] - demo_results[m]["score"]) < 1e-9
