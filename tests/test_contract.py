"""Every module returns the shared ModuleResult / Finding contract."""
import pytest

from utils.common import SEVERITIES

FINDING_KEYS = {"id", "module", "title", "severity", "points_lost", "evidence", "source", "attack_ids", "remediation_ids"}
RESULT_KEYS = {"module", "score", "risk_level", "findings", "ml", "rule_ml_agreement", "uncertain", "explanations", "assessed"}


@pytest.mark.parametrize("module", ["password", "email", "url", "permission", "device"])
def test_contract(demo_results, module):
    r = demo_results[module]
    assert RESULT_KEYS <= set(r)
    assert r["module"] == module and r["assessed"] is True
    assert 0 <= r["score"] <= 100
    for f in r["findings"]:
        assert FINDING_KEYS <= set(f)
        assert f["severity"] in SEVERITIES
        assert f["source"] in ("rule", "ml")
        assert f["id"].isupper()
    # module invariant: findings sum exactly to the module deficit
    assert abs(100 - sum(f["points_lost"] for f in r["findings"]) - r["score"]) < 1e-9
