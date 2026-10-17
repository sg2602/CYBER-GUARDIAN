"""Module 5 - Device Security Audit (self-reported questionnaire; NOT an antivirus)."""
from __future__ import annotations

from utils.common import make_finding, make_module_result

MODULE = "device"
ANSWERS = ("YES", "NO", "NOT_SURE")

# key -> (question, finding id, finding title, severity, weight, ATT&CK, remediation)
QUESTIONS = {
    "os_updated": ("Is your operating system up to date?", "DEV_OS_OUTDATED", "Operating system not up to date",
                   "HIGH", 15, ["T1190", "T1203"], ["ACT_UPDATE_OS"]),
    "auto_updates": ("Are automatic updates enabled?", "DEV_NO_AUTO_UPDATES", "Automatic updates disabled",
                     "MEDIUM", 12, ["T1203"], ["ACT_AUTO_UPDATES"]),
    "firewall": ("Is the firewall enabled?", "DEV_NO_FIREWALL", "Firewall disabled", "MEDIUM", 8, ["T1133"], ["ACT_FIREWALL"]),
    "antivirus": ("Is antivirus / security software active?", "DEV_NO_ANTIVIRUS", "No antivirus / security software",
                  "MEDIUM", 8, ["T1204"], ["ACT_ANTIVIRUS"]),
    "screen_lock": ("Is a screen lock (PIN/password/biometric) set?", "DEV_NO_SCREEN_LOCK", "No screen lock",
                    "HIGH", 12, ["T1461"], ["ACT_SCREEN_LOCK"]),
    "disk_encryption": ("Is disk / device encryption enabled?", "DEV_NO_DISK_ENCRYPTION", "Disk encryption disabled",
                        "MEDIUM", 10, ["T1005"], ["ACT_DISK_ENCRYPTION"]),
    "secure_boot": ("Is Secure Boot enabled?", "DEV_NO_SECURE_BOOT", "Secure Boot disabled", "LOW", 5, ["T1542"],
                    ["ACT_SECURE_BOOT"]),
    "mfa": ("Is multi-factor authentication enabled on your main accounts?", "DEV_NO_MFA",
            "No multi-factor authentication on main accounts", "HIGH", 15, ["T1078", "T1110"], ["ACT_ENABLE_MFA"]),
    "backup": ("Do you have a recent backup (last 30 days)?", "DEV_NO_BACKUP", "No recent backup", "MEDIUM", 8,
               ["T1486"], ["ACT_BACKUP"]),
    "bluetooth": ("Is Bluetooth off / non-discoverable when unused?", "DEV_BLUETOOTH_EXPOSED",
                  "Bluetooth left discoverable", "LOW", 3, ["T1011.001"], ["ACT_BLUETOOTH"]),
    "public_wifi": ("Do you avoid public Wi-Fi or use a VPN on it?", "DEV_PUBLIC_WIFI_UNSAFE",
                    "Uses public Wi-Fi without VPN", "LOW", 4, ["T1557"], ["ACT_VPN_PUBLIC_WIFI"]),
}
assert sum(q[4] for q in QUESTIONS.values()) == 100
DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def audit_device(answers: dict[str, str]) -> dict:
    """answers: question key -> YES | NO | NOT_SURE.  Missing keys count as NOT_SURE.
    'Not sure' counts as half risk and yields a *_UNSURE finding (does not trigger chains that need a definite NO)."""
    f = []
    norm = {}
    for key, (q, fid, title, sev, w, attack, rem) in QUESTIONS.items():
        a = str(answers.get(key, "NOT_SURE")).upper().replace(" ", "_")
        if a not in ANSWERS:
            raise ValueError(f"Invalid answer {a!r} for {key}")
        norm[key] = a
        if a == "NO":
            f.append(make_finding(fid, MODULE, title, sev, w, f"Answered NO to: {q}", attack_ids=attack, remediation_ids=rem))
        elif a == "NOT_SURE":
            f.append(make_finding(fid + "_UNSURE", MODULE, title + " (not sure)", DOWNGRADE[sev], w / 2,
                                  f"Answered 'Not sure' to: {q} (counted as half risk)", attack_ids=attack,
                                  remediation_ids=rem))
    return make_module_result(MODULE, f, extra={"answers": norm})


def inspect_windows_security() -> dict[str, str]:
    """Inspect local Windows security settings using native read-only PowerShell queries.

    Privacy & Safety Guarantee:
    - 100% read-only queries (Get-MpComputerStatus, Get-NetFirewallProfile, etc.).
    - Zero personal files or documents inspected.
    - Zero network transmission (100% local in-memory execution).
    - Returns a mapping of detected question keys to 'YES' | 'NO' | 'NOT_SURE'.
    """
    import subprocess
    import sys

    results: dict[str, str] = {}
    if sys.platform != "win32":
        return results

    # 1. Antivirus / Real-time Protection
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
            capture_output=True, text=True, timeout=3.0
        )
        out = r.stdout.strip()
        if "True" in out:
            results["antivirus"] = "YES"
        elif "False" in out:
            results["antivirus"] = "NO"
    except Exception:
        pass

    # 2. Windows Firewall
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-NetFirewallProfile).Enabled"],
            capture_output=True, text=True, timeout=3.0
        )
        out = r.stdout.strip()
        if "True" in out and "False" not in out:
            results["firewall"] = "YES"
        elif "False" in out:
            results["firewall"] = "NO"
    except Exception:
        pass

    # 3. BitLocker Drive Encryption
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus"],
            capture_output=True, text=True, timeout=3.0
        )
        out = r.stdout.strip()
        if "1" in out or "On" in out:
            results["disk_encryption"] = "YES"
        elif "0" in out or "Off" in out:
            results["disk_encryption"] = "NO"
    except Exception:
        pass

    # 4. Automatic Updates
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType"],
            capture_output=True, text=True, timeout=3.0
        )
        out = r.stdout.strip()
        if "Automatic" in out:
            results["auto_updates"] = "YES"
        elif "Disabled" in out:
            results["auto_updates"] = "NO"
    except Exception:
        pass

    # 5. Secure Boot
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"],
            capture_output=True, text=True, timeout=3.0
        )
        out = r.stdout.strip()
        if "True" in out:
            results["secure_boot"] = "YES"
        elif "False" in out:
            results["secure_boot"] = "NO"
    except Exception:
        pass

    return results

