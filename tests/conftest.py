import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.device_audit import QUESTIONS, audit_device  # noqa: E402
from modules.email_analyzer import analyze_email  # noqa: E402
from modules.password_audit import audit_password  # noqa: E402
from modules.permission_audit import audit_permissions  # noqa: E402
from modules.url_scanner import scan_url  # noqa: E402
from utils import demo_inputs as d  # noqa: E402

GOOD_DEVICE = {k: "YES" for k in QUESTIONS}


def device(**over):
    a = dict(GOOD_DEVICE)
    a.update(over)
    return audit_device(a)


@pytest.fixture(scope="session")
def demo_results():
    return {"password": audit_password(d.DEMO_PASSWORD), "email": analyze_email(d.DEMO_EMAIL),
            "url": scan_url(d.DEMO_URL), "permission": audit_permissions("Calculator", d.DEMO_APP["permissions"]),
            "device": audit_device(d.DEMO_DEVICE)}


@pytest.fixture(scope="session")
def good_results():
    return {"password": audit_password("lantern-Orbit-93-quiet-Mango"), "email": analyze_email(d.DEMO_LEGIT_EMAIL),
            "url": scan_url("https://en.wikipedia.org/wiki/Computer_security"),
            "permission": audit_permissions("Calculator", ["INTERNET"]), "device": audit_device(GOOD_DEVICE)}
