from modules.password_audit import audit_password, estimate_entropy


def ids(r):
    return {f["id"] for f in r["findings"]}


def test_spec_example_samriddhi():
    r = audit_password("Samriddhi123")
    assert r["risk_level"] == "HIGH"
    assert {"PWD_NAME_DIGITS", "PWD_NO_SPECIAL", "PWD_LOW_ENTROPY"} <= ids(r)
    c = r["extra"]["checks"]
    assert c["uppercase"] and c["lowercase"] and c["digits"] and not c["special"]


def test_common_and_leet():
    assert "PWD_COMMON" in ids(audit_password("password"))
    assert "PWD_COMMON" in ids(audit_password("P@ssw0rd"))
    assert audit_password("123456")["risk_level"] == "CRITICAL"


def test_patterns():
    assert "PWD_SEQUENTIAL" in ids(audit_password("Xk9abcdQ!"))
    assert "PWD_REPEATED_CHARS" in ids(audit_password("Zq!aaaa9Lm"))
    assert "PWD_YEAR_PATTERN" in ids(audit_password("Rahul@1998"))
    assert "PWD_TOO_SHORT" in ids(audit_password("Ab1!"))


def test_strong_password_low_risk():
    r = audit_password("x7#Kq9!mZ2@vLp4$")
    assert r["risk_level"] == "LOW" and r["score"] >= 90


def test_reuse_flag():
    assert "PWD_REUSED" in ids(audit_password("x7#Kq9!mZ2@vLp4$", reused=True))


def test_entropy_penalises_patterns():
    e1 = estimate_entropy("Samriddhi123")
    assert e1["effective_bits"] < e1["naive_bits"]
    assert e1["effective_bits"] < 40


def test_password_never_in_output():
    pw = "Zebracorn#2024secret"
    r = audit_password(pw)
    blob = repr(r).lower()
    assert pw.lower() not in blob
    assert "zebracorn" not in blob and "secret" not in blob


def test_hibp_k_anonymity_breach_detection(monkeypatch):
    import modules.password_audit as pa
    # Mock HIBP API response to ensure deterministic, fast, offline-safe unit testing
    monkeypatch.setattr(pa, "check_hibp_pwned", lambda pw, timeout=3.0: 120 if "ManchesterUnited1!" in pw else 0)
    r_breached = pa.audit_password("ManchesterUnited1!", check_hibp=True)
    assert "PWD_PWNED" in ids(r_breached)
    assert r_breached["extra"]["breach_count"] == 120
    # Safe password is not breached
    r_safe = pa.audit_password("x7#Kq9!mZ2@vLp4$Unique99", check_hibp=True)
    assert "PWD_PWNED" not in ids(r_safe)
    assert r_safe["extra"]["breach_count"] == 0


def test_breached_password_triggers_credential_stuffing(monkeypatch):
    from conftest import device
    from risk.risk_engine import score
    import modules.password_audit as pa
    monkeypatch.setattr(pa, "check_hibp_pwned", lambda pw, timeout=3.0: 120)
    res = {"password": pa.audit_password("ManchesterUnited1!", check_hibp=True), "device": device(mfa="NO")}
    s = score(res)
    assert "CH_CREDENTIAL_STUFFING" in {c["id"] for c in s["chains"]}
    assert s["score"] <= 59.0


