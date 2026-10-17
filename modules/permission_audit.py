"""Module 4 - Mobile App Permission Audit (rule-based + app-category baseline).

Input: an AndroidManifest.xml (text) OR an app category plus a list of permission groups.
The manifest is parsed in memory only and never stored.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from utils.common import make_finding, make_module_result

MODULE = "permission"

# --- Severity scale: Normal / Low / Medium / High / Critical --------------------------
SEVERITY_SCALE = {          # scale level -> (finding severity, points when UNEXPECTED for the category)
    "Normal": ("INFO", 0),
    "Low": ("LOW", 2),
    "Medium": ("MEDIUM", 6),
    "High": ("HIGH", 12),
    "Critical": ("CRITICAL", 25),
}
EXPECTED_FACTOR = 0.25      # an expected-but-sensitive permission still costs 25% of its points

# permission group -> (scale level, human label, MITRE ATT&CK for Mobile technique IDs)
PERMISSION_GROUPS = {
    "INTERNET": ("Normal", "Internet access", []),
    "NOTIFICATIONS": ("Low", "Post notifications", []),
    "BLUETOOTH": ("Low", "Bluetooth", []),
    "STORAGE": ("Medium", "Storage / media files", ["T1533"]),
    "LOCATION_COARSE": ("Medium", "Approximate location", ["T1430"]),
    "PHONE": ("Medium", "Phone state / make calls", ["T1426"]),
    "CALENDAR": ("Medium", "Calendar", ["T1636"]),
    "BODY_SENSORS": ("Medium", "Body sensors", []),
    "CAMERA": ("High", "Camera", ["T1512"]),
    "MICROPHONE": ("High", "Microphone", ["T1429"]),
    "CONTACTS": ("High", "Contacts", ["T1636.003"]),
    "LOCATION_FINE": ("High", "Precise location", ["T1430"]),
    "BACKGROUND_LOCATION": ("High", "Background location", ["T1430"]),
    "SMS": ("High", "Read / send / receive SMS", ["T1636.004", "T1582"]),
    "CALL_LOG": ("High", "Call log", ["T1636.002"]),
    "OVERLAY": ("High", "Draw over other apps (overlay)", ["T1417.002"]),
    "INSTALL_PACKAGES": ("High", "Install other apps", ["T1407"]),
    "ACCESSIBILITY": ("Critical", "Accessibility service", ["T1453", "T1417"]),
    "DEVICE_ADMIN": ("Critical", "Device administrator", ["T1626.001"]),
}

ANDROID_TO_GROUP = {
    "INTERNET": "INTERNET", "ACCESS_NETWORK_STATE": "INTERNET", "ACCESS_WIFI_STATE": "INTERNET",
    "POST_NOTIFICATIONS": "NOTIFICATIONS", "BLUETOOTH": "BLUETOOTH", "BLUETOOTH_CONNECT": "BLUETOOTH",
    "BLUETOOTH_SCAN": "BLUETOOTH", "BLUETOOTH_ADMIN": "BLUETOOTH",
    "READ_EXTERNAL_STORAGE": "STORAGE", "WRITE_EXTERNAL_STORAGE": "STORAGE", "MANAGE_EXTERNAL_STORAGE": "STORAGE",
    "READ_MEDIA_IMAGES": "STORAGE", "READ_MEDIA_VIDEO": "STORAGE", "READ_MEDIA_AUDIO": "STORAGE",
    "ACCESS_COARSE_LOCATION": "LOCATION_COARSE", "ACCESS_FINE_LOCATION": "LOCATION_FINE",
    "ACCESS_BACKGROUND_LOCATION": "BACKGROUND_LOCATION",
    "READ_PHONE_STATE": "PHONE", "CALL_PHONE": "PHONE", "READ_PHONE_NUMBERS": "PHONE", "ANSWER_PHONE_CALLS": "PHONE",
    "READ_CALENDAR": "CALENDAR", "WRITE_CALENDAR": "CALENDAR", "BODY_SENSORS": "BODY_SENSORS",
    "CAMERA": "CAMERA", "RECORD_AUDIO": "MICROPHONE", "READ_CONTACTS": "CONTACTS", "WRITE_CONTACTS": "CONTACTS",
    "GET_ACCOUNTS": "CONTACTS",
    "READ_SMS": "SMS", "SEND_SMS": "SMS", "RECEIVE_SMS": "SMS", "RECEIVE_MMS": "SMS", "RECEIVE_WAP_PUSH": "SMS",
    "READ_CALL_LOG": "CALL_LOG", "WRITE_CALL_LOG": "CALL_LOG", "PROCESS_OUTGOING_CALLS": "CALL_LOG",
    "SYSTEM_ALERT_WINDOW": "OVERLAY", "REQUEST_INSTALL_PACKAGES": "INSTALL_PACKAGES", "INSTALL_PACKAGES": "INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE": "ACCESSIBILITY", "BIND_DEVICE_ADMIN": "DEVICE_ADMIN",
}

# Expected permission groups per app category (purpose baseline)
CATEGORY_EXPECTED = {
    "Calculator": {"INTERNET"},
    "Flashlight": {"INTERNET", "CAMERA"},  # camera flash API
    "Notes": {"INTERNET", "STORAGE", "NOTIFICATIONS"},
    "Game": {"INTERNET", "NOTIFICATIONS", "STORAGE", "BLUETOOTH"},
    "Camera": {"INTERNET", "CAMERA", "MICROPHONE", "STORAGE", "LOCATION_COARSE", "LOCATION_FINE"},
    "Maps": {"INTERNET", "LOCATION_COARSE", "LOCATION_FINE", "BACKGROUND_LOCATION", "NOTIFICATIONS", "STORAGE", "MICROPHONE"},
    "Messaging": {"INTERNET", "CONTACTS", "CAMERA", "MICROPHONE", "STORAGE", "NOTIFICATIONS", "SMS", "PHONE",
                  "LOCATION_COARSE", "LOCATION_FINE", "OVERLAY", "CALL_LOG", "BLUETOOTH"},
    "Banking": {"INTERNET", "NOTIFICATIONS", "CAMERA", "SMS", "PHONE", "LOCATION_COARSE", "LOCATION_FINE", "CONTACTS"},
    "Social": {"INTERNET", "CAMERA", "MICROPHONE", "STORAGE", "NOTIFICATIONS", "CONTACTS", "LOCATION_COARSE", "LOCATION_FINE"},
    "Fitness": {"INTERNET", "LOCATION_COARSE", "LOCATION_FINE", "BACKGROUND_LOCATION", "BODY_SENSORS", "NOTIFICATIONS", "BLUETOOTH"},
    "Music": {"INTERNET", "STORAGE", "NOTIFICATIONS", "BLUETOOTH", "MICROPHONE"},
    "Shopping": {"INTERNET", "NOTIFICATIONS", "CAMERA", "LOCATION_COARSE", "STORAGE"},
}
CATEGORIES = list(CATEGORY_EXPECTED)


def parse_manifest(xml_text: str) -> tuple[set[str], list[str]]:
    """Return (permission groups, unknown dangerous-looking permissions) from AndroidManifest.xml text."""
    groups, other = set(), []
    names = []
    try:
        root = ET.fromstring(xml_text)
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            for k, v in el.attrib.items():
                if k.split("}")[-1] == "name" and tag in ("uses-permission", "uses-permission-sdk-23"):
                    names.append(v)
                if k.split("}")[-1] == "permission" and tag == "service":
                    names.append(v)  # e.g. BIND_ACCESSIBILITY_SERVICE on a <service>
    except ET.ParseError:
        names = re.findall(r"android\.permission\.[A-Z_]+", xml_text)
    for n in names:
        short = n.split(".")[-1]
        if short in ANDROID_TO_GROUP:
            groups.add(ANDROID_TO_GROUP[short])
        elif short.isupper():
            other.append(short)
    return groups, sorted(set(other))


def audit_permissions(category: str, groups: set[str] | list[str], app_name: str = "App") -> dict:
    if category not in CATEGORY_EXPECTED:
        raise ValueError(f"Unknown category {category}")
    groups = {g for g in groups if g in PERMISSION_GROUPS}
    expected = CATEGORY_EXPECTED[category]
    f = []
    unexpected = []
    for g in sorted(groups, key=lambda g: -SEVERITY_SCALE[PERMISSION_GROUPS[g][0]][1]):
        level, label, attack = PERMISSION_GROUPS[g]
        sev, pts = SEVERITY_SCALE[level]
        if level == "Normal":
            continue
        if g in expected:
            f.append(make_finding(f"PERM_SENSITIVE_{g}", MODULE, f"{label} (expected for {category})", "LOW",
                                  pts * EXPECTED_FACTOR, f"{level}-sensitivity permission consistent with app purpose",
                                  attack_ids=attack, remediation_ids=_remediation(g)))
        else:
            unexpected.append(g)
            f.append(make_finding(f"PERM_UNEXPECTED_{g}", MODULE, f"{label} not expected for a {category} app", sev, pts,
                                  f"{level}-sensitivity permission outside the {category} baseline",
                                  attack_ids=attack, remediation_ids=_remediation(g)))
    sensitive_unexpected = [g for g in unexpected if PERMISSION_GROUPS[g][0] in ("High", "Critical")]
    if len(unexpected) >= 3 or len(sensitive_unexpected) >= 2:
        f.append(make_finding("PERM_EXCESSIVE", MODULE, "Permissions excessive for stated purpose", "MEDIUM", 10,
                              "The requested permissions appear excessive relative to the stated application purpose "
                              f"({len(unexpected)} unexpected for {category})", attack_ids=[],
                              remediation_ids=["ACT_REVOKE_PERMISSIONS", "ACT_UNINSTALL_APP"]))
    extra = {"category": category, "app_name": app_name, "requested": sorted(groups), "unexpected": unexpected}
    res = make_module_result(MODULE, f, extra=extra)
    res["extra"]["verdict"] = {"LOW": "LOW PRIVACY RISK", "MODERATE": "MODERATE PRIVACY RISK",
                               "HIGH": "HIGH PRIVACY RISK", "CRITICAL": "CRITICAL PRIVACY RISK"}[res["risk_level"]]
    return res


def _remediation(g: str) -> list[str]:
    if g in ("ACCESSIBILITY", "DEVICE_ADMIN", "OVERLAY", "INSTALL_PACKAGES"):
        return ["ACT_REMOVE_HIGH_PRIV", "ACT_UNINSTALL_APP"]
    if g == "BACKGROUND_LOCATION":
        return ["ACT_DISABLE_BG_LOCATION", "ACT_REVOKE_PERMISSIONS"]
    return ["ACT_REVOKE_PERMISSIONS", "ACT_UNINSTALL_APP"]


def audit_manifest(xml_text: str, category: str) -> dict:
    groups, other = parse_manifest(xml_text)
    res = audit_permissions(category, groups, app_name="Uploaded manifest")
    res["extra"]["unmapped_permissions"] = other
    return res
