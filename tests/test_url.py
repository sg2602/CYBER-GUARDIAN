from modules.url_scanner import rule_findings, scan_url
from utils.feature_extraction import extract_features, parse


def rids(u):
    return {f["id"] for f in rule_findings(u)[0]}


def test_spec_example():
    r = scan_url("http://paypa1-login-example.com/verify")
    assert r["risk_level"] in ("HIGH", "CRITICAL")
    assert {"URL_NO_HTTPS", "URL_BRAND_LOOKALIKE", "URL_SENSITIVE_KEYWORDS"} <= {f["id"] for f in r["findings"]}
    assert r["ml"]["shap_top"], "SHAP explanation expected for ML module"


def test_structural_rules():
    assert "URL_IP_HOST" in rids("http://192.168.1.10/login")
    assert "URL_AT_SYMBOL" in rids("http://www.paypal.com@evil.ru/")
    assert "URL_PUNYCODE" in rids("http://xn--pple-43d.com/")
    assert "URL_SHORTENER" in rids("https://bit.ly/abc123")
    assert "URL_SUSPICIOUS_TLD" in rids("https://free-gift.xyz/")
    assert "URL_BRAND_MISPLACED" in rids("http://paypal.com.secure-check.info/login")


def test_registered_domain_parsing():
    assert parse("https://a.b.example.co.in/x")["registered_domain"] == "example.co.in"
    assert parse("example.com")["scheme"] == "http"
    assert parse("https://www.google.com/")["subdomains"] == []


def test_official_domain_allowlist():
    r = scan_url("https://www.amazon.in/gp/your-account/order-history")
    assert r["extra"]["official_domain"] is True
    assert r["risk_level"] in ("LOW", "MODERATE")


def test_trailing_slash_normalised():
    a = extract_features("https://www.iitb.ac.in/")["features"]
    b = extract_features("https://www.iitb.ac.in")["features"]
    assert a["path_length"] == b["path_length"] == 0


def test_rules_only_and_ml_only_modes():
    u = "http://kyc-update-hdfc.top/verify"
    ro = scan_url(u, use_ml=False)
    assert ro["ml"] is None and not any(f["source"] == "ml" for f in ro["findings"])
    mo = scan_url(u, use_rules=False)
    assert all(f["source"] == "ml" for f in mo["findings"])
