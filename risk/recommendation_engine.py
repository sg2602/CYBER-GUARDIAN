"""Recommendation Engine: Finding ID -> risk level -> Action IDs -> Priority.

Priority: Immediate (finding CRITICAL/HIGH or breaks an attack chain), Soon (MEDIUM),
Good practice (LOW/INFO).  Each action lists the findings it resolves (fnmatch
patterns), which the What-If simulator uses to re-score.
"""
from __future__ import annotations

import fnmatch

EFFORT_WEIGHT = {"Low": 1, "Medium": 2, "High": 3}
PRIORITIES = ["Immediate", "Soon", "Good practice"]

ACTIONS = {
    "ACT_ENABLE_MFA": {
        "title": "Enable multi-factor authentication (MFA)", "effort": "Low",
        "resolves": ["DEV_NO_MFA", "DEV_NO_MFA_UNSURE"],
        "steps": ["Turn on 2-step verification for email, banking and social accounts (authenticator app or passkey preferred over SMS).",
                  "Save the backup codes offline.",
                  "With MFA a stolen password alone is no longer enough to log in."]},
    "ACT_LONG_PASSWORD": {
        "title": "Replace the weak password with a long, unique passphrase", "effort": "Low",
        "resolves": ["PWD_*"],
        "steps": ["Use 16+ characters - e.g. four or more random unrelated words with separators.",
                  "Avoid names, birth years, keyboard patterns (qwerty, 123) and dictionary words with simple substitutions.",
                  "Generate and store it in a password manager."]},
    "ACT_UNIQUE_PASSWORDS": {
        "title": "Stop password reuse - use a password manager", "effort": "Low",
        "resolves": ["PWD_REUSED"],
        "steps": ["Install a reputable password manager (e.g. Bitwarden, 1Password, KeePassXC).",
                  "Give every site its own generated password, starting with email and banking.",
                  "Change the reused password everywhere it was used."]},
    "ACT_REPORT_PHISHING": {
        "title": "Do not act on the suspicious email - verify independently and report it", "effort": "Low",
        "resolves": ["EMAIL_*"],
        "steps": ["Do not click embedded links or open attachments; do not reply.",
                  "Verify by contacting the organisation through its official app/website typed by hand.",
                  "Never provide passwords, OTPs, PINs or card details by email.",
                  "Report it (Report-phishing button / forward to the brand's abuse address), then delete it."]},
    "ACT_REPORT_INDIA_SCAM": {
        "title": "Treat as a payment / KYC scam - report to 1930 / cybercrime.gov.in", "effort": "Low",
        "resolves": ["EMAIL_IN_*"],
        "steps": ["You NEVER need to enter a UPI PIN to RECEIVE money - decline any collect request you did not initiate.",
                  "Banks do not ask for KYC updates through links or SMS; visit the branch or the official app.",
                  "Police/CBI do not conduct 'digital arrests' over video calls - disconnect.",
                  "Report on the national helpline 1930 or https://cybercrime.gov.in, and use Sanchar Saathi 'Chakshu' for fraud SMS/calls."]},
    "ACT_AVOID_URL": {
        "title": "Do not open the risky link; use the official site instead", "effort": "Low",
        "resolves": ["URL_*"],
        "steps": ["Do not enter credentials on the page.",
                  "Type the official address yourself or use the official app.",
                  "If already opened and credentials were entered, change the password immediately and enable MFA."]},
    "ACT_REVOKE_PERMISSIONS": {
        "title": "Revoke permissions the app does not need", "effort": "Low",
        "resolves": ["PERM_UNEXPECTED_CAMERA", "PERM_UNEXPECTED_MICROPHONE", "PERM_UNEXPECTED_CONTACTS",
                     "PERM_UNEXPECTED_LOCATION_*", "PERM_UNEXPECTED_SMS", "PERM_UNEXPECTED_CALL_LOG",
                     "PERM_UNEXPECTED_STORAGE", "PERM_UNEXPECTED_PHONE", "PERM_UNEXPECTED_CALENDAR",
                     "PERM_UNEXPECTED_BODY_SENSORS", "PERM_UNEXPECTED_NOTIFICATIONS", "PERM_UNEXPECTED_BLUETOOTH",
                     "PERM_EXCESSIVE"],
        "steps": ["Settings > Apps > [app] > Permissions: set unneeded ones to 'Don't allow'.",
                  "Prefer 'Only while using the app' / 'Ask every time' for camera, microphone and location.",
                  "Review Android's Privacy dashboard for recent camera/mic/location use."]},
    "ACT_DISABLE_BG_LOCATION": {
        "title": "Disable background location access", "effort": "Low",
        "resolves": ["PERM_*_BACKGROUND_LOCATION"],
        "steps": ["Settings > Location > App location permissions > set to 'Allow only while using the app'."]},
    "ACT_REMOVE_HIGH_PRIV": {
        "title": "Remove accessibility / overlay / device-admin rights from the app", "effort": "Low",
        "resolves": ["PERM_*_ACCESSIBILITY", "PERM_*_DEVICE_ADMIN", "PERM_*_OVERLAY", "PERM_*_INSTALL_PACKAGES"],
        "steps": ["Settings > Accessibility > Installed apps: turn the app off.",
                  "Settings > Security > Device admin apps: deactivate it.",
                  "Settings > Apps > Special access > Display over other apps / Install unknown apps: deny."]},
    "ACT_UNINSTALL_APP": {
        "title": "Uninstall the app (or replace it with a trusted alternative)", "effort": "Medium",
        "resolves": ["PERM_*"],
        "steps": ["Uninstall from Settings > Apps; if blocked, first remove device-admin rights.",
                  "Install apps only from Google Play and check the developer and reviews.",
                  "Run Google Play Protect scan afterwards."]},
    "ACT_UPDATE_OS": {"title": "Install pending operating-system updates", "effort": "Medium",
                      "resolves": ["DEV_OS_OUTDATED*"],
                      "steps": ["Install all pending OS and security updates now and restart."]},
    "ACT_AUTO_UPDATES": {"title": "Turn on automatic updates", "effort": "Low", "resolves": ["DEV_NO_AUTO_UPDATES*"],
                         "steps": ["Enable automatic OS, browser and app-store updates."]},
    "ACT_FIREWALL": {"title": "Enable the firewall", "effort": "Low", "resolves": ["DEV_NO_FIREWALL*"],
                     "steps": ["Windows: Defender Firewall on for all profiles. macOS: System Settings > Network > Firewall."]},
    "ACT_ANTIVIRUS": {"title": "Enable built-in security software", "effort": "Low", "resolves": ["DEV_NO_ANTIVIRUS*"],
                      "steps": ["Windows: keep Microsoft Defender real-time protection on. Android: keep Play Protect on."]},
    "ACT_SCREEN_LOCK": {"title": "Set a screen lock with auto-lock", "effort": "Low", "resolves": ["DEV_NO_SCREEN_LOCK*"],
                        "steps": ["Use a 6+ digit PIN / password or biometrics; auto-lock after 1-5 minutes."]},
    "ACT_DISK_ENCRYPTION": {"title": "Enable full-disk encryption", "effort": "Medium",
                            "resolves": ["DEV_NO_DISK_ENCRYPTION*"],
                            "steps": ["Windows: BitLocker / Device Encryption. macOS: FileVault. Android/iOS: on by default with a screen lock.",
                                      "Store the recovery key somewhere safe and offline."]},
    "ACT_SECURE_BOOT": {"title": "Enable Secure Boot in firmware settings", "effort": "High",
                        "resolves": ["DEV_NO_SECURE_BOOT*"],
                        "steps": ["Enable Secure Boot in UEFI/BIOS settings (check the vendor guide first)."]},
    "ACT_BACKUP": {"title": "Set up automatic backups (3-2-1 rule)", "effort": "Medium", "resolves": ["DEV_NO_BACKUP*"],
                   "steps": ["Keep 3 copies on 2 media with 1 offline/off-site; schedule automatic backups and test a restore."]},
    "ACT_BLUETOOTH": {"title": "Turn Bluetooth off / non-discoverable when unused", "effort": "Low",
                      "resolves": ["DEV_BLUETOOTH_EXPOSED*"], "steps": ["Disable Bluetooth discovery when not pairing."]},
    "ACT_VPN_PUBLIC_WIFI": {"title": "Use a trusted VPN or mobile data on public Wi-Fi", "effort": "Medium",
                            "resolves": ["DEV_PUBLIC_WIFI_UNSAFE*"],
                            "steps": ["Avoid logging in to banking on public Wi-Fi; use mobile hotspot or a reputable VPN."]},
}


def finding_resolved_by(action_id: str, finding_id: str) -> bool:
    return any(fnmatch.fnmatchcase(finding_id, p) for p in ACTIONS[action_id]["resolves"])


def _priority(sev: str) -> str:
    return "Immediate" if sev in ("CRITICAL", "HIGH") else ("Soon" if sev == "MEDIUM" else "Good practice")


def recommend(results: dict, scored: dict) -> list[dict]:
    """Return recommendations grouped by priority (Immediate first)."""
    recs: dict[str, dict] = {}
    all_f = [f for r in results.values() if r and r.get("assessed") for f in r["findings"]]
    for f in all_f + scored.get("correlation_findings", []):
        if f["source"] == "ml" and f["severity"] == "INFO":
            continue
        for aid in f["remediation_ids"]:
            if aid not in ACTIONS:
                continue
            pr = "Immediate" if f["source"] == "correlation" else _priority(f["severity"])
            rec = recs.setdefault(aid, {"action_id": aid, **{k: ACTIONS[aid][k] for k in ("title", "effort", "steps")},
                                        "priority": pr, "triggered_by": [], "breaks_chains": []})
            if PRIORITIES.index(pr) < PRIORITIES.index(rec["priority"]):
                rec["priority"] = pr
            if f["source"] == "correlation":
                rec["breaks_chains"].append(f["id"])
            elif f["id"] not in rec["triggered_by"]:
                rec["triggered_by"].append(f["id"])
    out = list(recs.values())
    out.sort(key=lambda r: (PRIORITIES.index(r["priority"]), EFFORT_WEIGHT[r["effort"]], -len(r["triggered_by"])))
    return out


def group_by_priority(recs: list[dict]) -> dict[str, list[dict]]:
    return {p: [r for r in recs if r["priority"] == p] for p in PRIORITIES}
