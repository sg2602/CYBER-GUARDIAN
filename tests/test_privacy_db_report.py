"""Privacy: raw inputs never reach the DB file or the report."""
from conftest import device
from database import database as db
from modules.email_analyzer import analyze_email
from modules.password_audit import audit_password
from modules.url_scanner import scan_url
from reports.report_generator import render_html, render_pdf
from risk.assessment import run_assessment

SECRET_PW = "Kalpavriksha#2026zz"
SECRET_URL = "http://secret-tracking-path.xyz/login/u/samriddhi.private/token123"
SECRET_BODY = "Please verify your account at once - unique body marker 7f3a9q - and send your OTP."


def make():
    res = {"password": audit_password(SECRET_PW, reused=True), "url": scan_url(SECRET_URL),
           "email": analyze_email("From: X <x@ex-ample.top>\nSubject: hi\n\n" + SECRET_BODY + " " + SECRET_URL),
           "device": device(mfa="NO")}
    return run_assessment(res)


def test_db_never_contains_raw_inputs(tmp_path):
    a = make()
    path = tmp_path / "t.db"
    db.save_assessment(a, path)
    raw = path.read_bytes()
    for s in (SECRET_PW, "Kalpavriksha", SECRET_URL, "samriddhi.private", "token123", "7f3a9q", "unique body marker"):
        assert s.encode() not in raw, s
    rows = db.list_assessments(path)
    assert rows[-1]["assessment_id"] == a["assessment_id"]
    assert db.get_findings(a["assessment_id"], path)
    assert {c["chain_id"] for c in db.get_chains(a["assessment_id"], path)} == {c["id"] for c in a["chains"]}


def test_report_never_contains_raw_inputs():
    a = make()
    html = render_html(a)
    for s in (SECRET_PW, "Kalpavriksha", SECRET_URL, "token123", "7f3a9q", "unique body marker"):
        assert s not in html, s
    assert "Cyber Safety Score" in html and a["assessment_id"] in html
    pdf = render_pdf(a)
    assert pdf[:4] == b"%PDF"


def test_history_improvement(tmp_path):
    from modules.password_audit import audit_password as ap
    p = tmp_path / "h.db"
    a1 = run_assessment({"password": ap("Samriddhi123"), "device": device(mfa="NO")}, with_whatif=False)
    a2 = run_assessment({"password": ap("x7#Kq9!mZ2@vLp4$"), "device": device()}, with_whatif=False)
    a2["created_at"] = "9999-01-01T00:00:00"
    db.save_assessment(a1, p)
    db.save_assessment(a2, p)
    assert db.improvement(p) > 0
