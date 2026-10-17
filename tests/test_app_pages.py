"""Headless Streamlit checks: every page renders without exceptions, empty and with a full assessment,
and the main scanner interactions work."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["app.py"] + sorted(str(p.relative_to(ROOT)) for p in (ROOT / "pages").glob("*.py"))


@pytest.mark.parametrize("page", PAGES)
@pytest.mark.parametrize("filled", [False, True])
def test_page_renders(page, filled, demo_results, tmp_path, monkeypatch):
    import database.database as db
    monkeypatch.setattr(db, "DEFAULT_DB", tmp_path / "app.db")
    at = AppTest.from_file(str(ROOT / page), default_timeout=180)
    at.session_state["results"] = dict(demo_results) if filled else {}
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def test_scanner_interactions():
    at = AppTest.from_file(str(ROOT / "pages/1_Security_Scanner.py"), default_timeout=180)
    at.run()
    # password demo
    next(b for b in at.button if "Samriddhi123" in b.label).click().run()
    assert at.session_state["results"]["password"]["risk_level"] == "HIGH"
    # device demo answers + score
    next(b for b in at.button if b.label.startswith("Fill demo answers")).click().run()
    next(b for b in at.button if b.label == "Score device").click().run()
    assert "DEV_NO_MFA" in {f["id"] for f in at.session_state["results"]["device"]["findings"]}
    # permission demo
    next(b for b in at.button if b.label.startswith("Demo: Calculator")).click().run()
    assert at.session_state["results"]["permission"]["risk_level"] in ("MODERATE", "HIGH")
    assert not at.exception
