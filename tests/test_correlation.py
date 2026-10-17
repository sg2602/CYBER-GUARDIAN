"""C1: chains fire / don't fire, escalation, critical floor, HIGH-chain cap."""
from conftest import device
from modules.email_analyzer import analyze_email
from modules.password_audit import audit_password
from modules.permission_audit import audit_permissions
from modules.url_scanner import scan_url
from risk.chain_rules import CHAIN_RULES, CRITICAL_FLOOR, ESCALATION_FACTOR, HIGH_CHAIN_FLOOR
from risk.risk_engine import score
from utils import demo_inputs as d

PHISH = d.DEMO_EMAIL


def chains(res):
    return {c["id"] for c in score(res)["chains"]}


def test_all_chain_ids_have_attack_mapping():
    assert len(CHAIN_RULES) >= 6
    for c in CHAIN_RULES:
        assert c["attack_ids"] and all(a.startswith("T1") for a in c["attack_ids"])


def test_account_takeover_fires():
    res = {"password": audit_password("Samriddhi123"), "email": analyze_email(PHISH), "device": device(mfa="NO")}
    s = score(res)
    assert "CH_ACCOUNT_TAKEOVER" in {c["id"] for c in s["chains"]}
    assert s["score"] <= CRITICAL_FLOOR and s["risk_level"] == "CRITICAL"


def test_account_takeover_needs_all_three_parts():
    assert "CH_ACCOUNT_TAKEOVER" not in chains({"password": audit_password("Samriddhi123"), "email": analyze_email(PHISH),
                                                "device": device()})  # MFA on
    assert "CH_ACCOUNT_TAKEOVER" not in chains({"password": audit_password("x7#Kq9!mZ2@vLp4$"), "email": analyze_email(PHISH),
                                                "device": device(mfa="NO")})  # strong password
    assert "CH_ACCOUNT_TAKEOVER" not in chains({"password": audit_password("Samriddhi123"), "email": analyze_email(d.DEMO_LEGIT_EMAIL),
                                                "device": device(mfa="NO")})  # no lure
    assert "CH_ACCOUNT_TAKEOVER" not in chains({"password": audit_password("Samriddhi123"), "email": analyze_email(PHISH),
                                                "device": device(mfa="NOT_SURE")})  # 'not sure' is not a definite NO


def test_account_takeover_via_malicious_login_url():
    res = {"password": audit_password("Monsoon2021", reused=True), "url": scan_url("http://paypa1-secure-login.com/signin/verify-account"),
           "device": device(mfa="NO")}
    assert "CH_ACCOUNT_TAKEOVER" in chains(res)


def test_cred_harvest_and_india_payment():
    c = chains({"email": analyze_email(PHISH)})
    assert {"CH_CRED_HARVEST", "CH_INDIA_PAYMENT_SCAM"} <= c
    assert not chains({"email": analyze_email(d.DEMO_LEGIT_EMAIL)})


def test_banking_trojan():
    res = {"permission": audit_permissions("Flashlight", ["SMS", "ACCESSIBILITY", "OVERLAY"])}
    s = score(res)
    assert "CH_BANKING_TROJAN" in {c["id"] for c in s["chains"]} and s["score"] <= CRITICAL_FLOOR
    assert "CH_BANKING_TROJAN" not in chains({"permission": audit_permissions("Flashlight", ["SMS", "OVERLAY"])})


def test_mobile_surveillance():
    assert "CH_MOBILE_SURVEILLANCE" in chains({"permission": audit_permissions("Calculator", ["MICROPHONE", "SMS"])})
    # expected for category -> no mismatch -> no chain
    assert "CH_MOBILE_SURVEILLANCE" not in chains({"permission": audit_permissions("Maps", ["LOCATION_FINE", "BACKGROUND_LOCATION"])})


def test_unrecoverable():
    assert "CH_UNRECOVERABLE" in chains({"device": device(backup="NO", auto_updates="NO", disk_encryption="NO")})
    assert "CH_UNRECOVERABLE" not in chains({"device": device(backup="NO", auto_updates="NO")})


def test_escalation_factor_applied():
    res = {"password": audit_password("Samriddhi123"), "email": analyze_email(PHISH), "device": device(mfa="NO")}
    s = score(res)
    cf = [f for f in s["correlation_findings"] if f["id"] == "CH_ACCOUNT_TAKEOVER"][0]
    w = s["weights"]
    part = {"PWD_LOW_ENTROPY", "PWD_NAME_DIGITS", "DEV_NO_MFA", "EMAIL_CREDENTIAL_REQUEST", "EMAIL_ACCOUNT_VERIFY",
            "EMAIL_IN_KYC", "EMAIL_LOGIN_LINK"}
    expected = ESCALATION_FACTOR * sum(w[m] * f["points_lost"] for m in w for f in res[m]["findings"] if f["id"] in part)
    assert abs(cf["points_lost"] - expected) < 1e-6


def test_critical_floor_caps_good_profile(good_results):
    res = dict(good_results)
    res["permission"] = audit_permissions("Flashlight", ["SMS", "ACCESSIBILITY", "OVERLAY"])
    s = score(res)
    assert s["baseline"] > 60  # plain average hides it
    assert s["score"] == CRITICAL_FLOOR and s["floor_applied"]


def test_high_chain_cap():
    res = {"password": audit_password("x7#Kq9!mZ2@vLp4$"), "device": device(backup="NO", auto_updates="NO", disk_encryption="NO")}
    s = score(res)
    assert s["baseline"] > HIGH_CHAIN_FLOOR and s["score"] == HIGH_CHAIN_FLOOR
    assert score(res, high_chain_floor=None)["score"] > HIGH_CHAIN_FLOOR  # ablation switch works


def test_no_chains_no_penalty(good_results):
    s = score(good_results)
    assert not s["chains"] and abs(s["score"] - s["baseline"]) < 1e-9


def test_credential_stuffing():
    # Reused password + no MFA triggers credential stuffing chain
    res = {"password": audit_password("Rahul@1998", reused=True), "device": device(mfa="NO")}
    s = score(res)
    assert "CH_CREDENTIAL_STUFFING" in {c["id"] for c in s["chains"]}
    assert s["score"] <= HIGH_CHAIN_FLOOR
    # MFA on breaks it
    assert "CH_CREDENTIAL_STUFFING" not in chains({"password": audit_password("Rahul@1998", reused=True), "device": device(mfa="YES")})
    # Non-reused strong password does not trigger it
    assert "CH_CREDENTIAL_STUFFING" not in chains({"password": audit_password("x7#Kq9!mZ2@vLp4$", reused=False), "device": device(mfa="NO")})


def test_coercion_scam():
    coercive_email = (
        "From: CBI Cyber Crime Cell <cbi.cyber.cell@gmail.com>\n"
        "Subject: Arrest warrant - money laundering case\n\n"
        "A money laundering case is registered against your Aadhaar number. You are under digital arrest. "
        "Join the video call immediately and transfer the verification amount to the safe account to avoid arrest."
    )
    s = score({"email": analyze_email(coercive_email)})
    assert "CH_COERCION_SCAM" in {c["id"] for c in s["chains"]}
    assert s["score"] <= HIGH_CHAIN_FLOOR


def test_attack_chain_graph_renders():
    from utils.ui import attack_chain_graph
    chain = {
        "id": "CH_ACCOUNT_TAKEOVER",
        "name": "Account takeover",
        "severity": "CRITICAL",
        "attack_ids": ["T1566", "T1110", "T1078"],
        "steps": ["Phishing lure", "Weak password guessed", "Valid account takeover"],
        "participants": ["PWD_REUSED", "DEV_NO_MFA"],
        "breaks_with": ["ACT_ENABLE_MFA", "ACT_LONG_PASSWORD"]
    }
    fig = attack_chain_graph(chain)
    assert fig is not None
    assert len(fig.data) >= 1


