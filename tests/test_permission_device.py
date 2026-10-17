from modules.device_audit import QUESTIONS, audit_device
from modules.permission_audit import audit_manifest, audit_permissions, parse_manifest
from utils import demo_inputs as d


def ids(r):
    return {f["id"] for f in r["findings"]}


def test_calculator_spec_example():
    r = audit_permissions("Calculator", ["INTERNET", "CAMERA", "MICROPHONE", "CONTACTS", "LOCATION_FINE"])
    assert r["risk_level"] == "HIGH"
    assert "PERM_EXCESSIVE" in ids(r)
    assert r["extra"]["verdict"] == "HIGH PRIVACY RISK"


def test_expected_permissions_are_cheap():
    r = audit_permissions("Maps", ["INTERNET", "LOCATION_FINE", "BACKGROUND_LOCATION"])
    assert r["risk_level"] == "LOW"
    assert all(f["id"].startswith("PERM_SENSITIVE_") for f in r["findings"])


def test_manifest_parsing():
    groups, other = parse_manifest(d.DEMO_MANIFEST)
    assert {"SMS", "OVERLAY", "ACCESSIBILITY", "CAMERA", "INTERNET"} <= groups
    r = audit_manifest(d.DEMO_MANIFEST, "Flashlight")
    assert "PERM_UNEXPECTED_ACCESSIBILITY" in ids(r)


def test_device_scoring():
    allyes = audit_device({k: "YES" for k in QUESTIONS})
    assert allyes["score"] == 100 and not allyes["findings"]
    allno = audit_device({k: "NO" for k in QUESTIONS})
    assert allno["score"] == 0
    unsure = audit_device({k: "NOT_SURE" for k in QUESTIONS})
    assert unsure["score"] == 50  # 'Not sure' = half risk
    assert all(f["id"].endswith("_UNSURE") for f in unsure["findings"])


def test_windows_security_inspection():
    from modules.device_audit import ANSWERS, inspect_windows_security
    posture = inspect_windows_security()
    assert isinstance(posture, dict)
    # Check that all keys belong to the valid QUESTIONS set
    for k, v in posture.items():
        assert k in QUESTIONS, f"Unexpected key: {k}"
        assert v in ANSWERS, f"Invalid value: {v}"
    # Verify strict privacy: only standard answer strings exist
    blob = repr(posture)
    assert "c:\\" not in blob.lower()
    assert "users" not in blob.lower()


def test_device_audit_with_inspected_posture():
    from modules.device_audit import inspect_windows_security
    detected = inspect_windows_security()
    # User provides manual MFA and backup alongside auto-detected values
    answers = {k: "NOT_SURE" for k in QUESTIONS}
    answers.update(detected)
    answers["mfa"] = "NO"
    answers["backup"] = "YES"
    r = audit_device(answers)
    assert r["assessed"] is True
    assert 0 <= r["score"] <= 100
    assert "DEV_NO_MFA" in ids(r)
    assert "DEV_NO_BACKUP" not in ids(r)

