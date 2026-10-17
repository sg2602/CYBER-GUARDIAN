"""C1 - Attack-chain definitions (data-driven) with MITRE ATT&CK mapping.

Condition grammar (evaluated recursively by correlation_engine):
  {"finding": "PWD_COMMON"}              finding present (fnmatch wildcards allowed, e.g. "PERM_*_SMS")
  {"any": [cond, ...]}                    at least one sub-condition true
  {"all": [cond, ...]}                    every sub-condition true
  {"at_least": n, "of": [cond, ...]}      n or more sub-conditions true
  {"module_max": ["email", 59]}           module assessed and its score <= value

Effects:
  {"type": "critical"}                               correlation finding with severity CRITICAL (-> critical floor)
  {"type": "module_tier", "module": m, "tier": T}    cap module m at tier T (e.g. HIGH -> score <= 59)
  {"type": "module_tier", "module": m, "raise": 1}   push module m one tier worse; if the module ends up
                                                     CRITICAL the chain finding itself becomes CRITICAL
                                                     (so the critical floor applies)
"""

ESCALATION_FACTOR = 0.3   # correlation penalty = 30% of the combined (weighted) deficit of participating findings
CRITICAL_FLOOR = 39.0      # any CRITICAL finding caps the Cyber Safety Score at 39
HIGH_CHAIN_FLOOR = 59.0    # any HIGH-severity attack chain caps the score at 59 (top of the HIGH band)

WEAK_PASSWORD = {"any": [{"finding": "PWD_COMMON"}, {"finding": "PWD_REUSED"}, {"finding": "PWD_PWNED"},
                         {"finding": "PWD_LOW_ENTROPY"}, {"finding": "PWD_NAME_DIGITS"}, {"finding": "PWD_TOO_SHORT"}]}
PHISHING_EMAIL = {"module_max": ["email", 59]}
CRED_PHISH = {"all": [PHISHING_EMAIL, {"any": [{"finding": "EMAIL_CREDENTIAL_REQUEST"}, {"finding": "EMAIL_ACCOUNT_VERIFY"},
                                                 {"finding": "EMAIL_IN_KYC"}, {"finding": "EMAIL_LOGIN_LINK"}]}]}
MALICIOUS_LOGIN_URL = {"all": [{"module_max": ["url", 59]}, {"finding": "URL_SENSITIVE_KEYWORDS"}]}

CHAIN_RULES = [
    {
        "id": "CH_ACCOUNT_TAKEOVER",
        "name": "Account takeover",
        "condition": {"all": [WEAK_PASSWORD, {"finding": "DEV_NO_MFA"}, {"any": [CRED_PHISH, MALICIOUS_LOGIN_URL]}]},
        "steps": ["Phishing lure / fake login page harvests credentials (T1566)",
                  "Weak or reused password is guessed or replayed (T1110)",
                  "No MFA - attacker logs in with valid account (T1078)"],
        "attack_ids": ["T1566", "T1110", "T1078"],
        "severity": "CRITICAL",
        "effect": {"type": "critical"},
        "explanation": "A weak/reused password, no MFA and an active credential lure combine into a direct path to "
                       "account takeover - each weakness alone is survivable, together they are not.",
        "breaks_with": ["ACT_ENABLE_MFA", "ACT_LONG_PASSWORD", "ACT_REPORT_PHISHING", "ACT_AVOID_URL"],
    },
    {
        "id": "CH_CRED_HARVEST",
        "name": "Credential harvest",
        "condition": {"all": [PHISHING_EMAIL, {"finding": "EMAIL_EMBEDDED_URL_HIGH"},
                              {"any": [{"finding": "EMAIL_LOGIN_LINK"}, {"finding": "EMAIL_ACCOUNT_VERIFY"},
                                       {"finding": "EMAIL_CREDENTIAL_REQUEST"}]}]},
        "steps": ["Phishing email delivered (T1566)", "Embedded link leads to high-risk login/verify page (T1566.002)",
                  "Credentials typed into attacker page"],
        "attack_ids": ["T1566.002"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "email", "raise": 1},
        "explanation": "The email's own link scored HIGH risk and points to a login/verify page - a working "
                       "credential-harvesting kit rather than mere spam.",
        "breaks_with": ["ACT_REPORT_PHISHING", "ACT_AVOID_URL"],
    },
    {
        "id": "CH_MOBILE_SURVEILLANCE",
        "name": "Mobile surveillance",
        "condition": {"all": [
            {"at_least": 2, "of": [{"finding": "PERM_*_SMS"}, {"finding": "PERM_*_MICROPHONE"},
                                   {"any": [{"finding": "PERM_*_LOCATION_FINE"}, {"finding": "PERM_*_LOCATION_COARSE"}]},
                                   {"finding": "PERM_*_BACKGROUND_LOCATION"}]},
            {"any": [{"finding": "PERM_UNEXPECTED_SMS"}, {"finding": "PERM_UNEXPECTED_MICROPHONE"},
                     {"finding": "PERM_UNEXPECTED_LOCATION_FINE"}, {"finding": "PERM_UNEXPECTED_LOCATION_COARSE"},
                     {"finding": "PERM_UNEXPECTED_BACKGROUND_LOCATION"}]}]},
        "steps": ["App requests sensor/SMS access unrelated to its purpose",
                  "Audio capture / location tracking (T1429, T1430)", "Data exfiltrated in background"],
        "attack_ids": ["T1429", "T1430"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "permission", "tier": "HIGH"},
        "explanation": "Two or more surveillance-capable permissions in an app whose category does not need them "
                       "is the profile of stalkerware / spyware.",
        "breaks_with": ["ACT_REVOKE_PERMISSIONS", "ACT_DISABLE_BG_LOCATION", "ACT_UNINSTALL_APP"],
    },
    {
        "id": "CH_BANKING_TROJAN",
        "name": "Banking-trojan profile",
        "condition": {"all": [{"finding": "PERM_*_SMS"}, {"finding": "PERM_*_ACCESSIBILITY"}, {"finding": "PERM_*_OVERLAY"}]},
        "steps": ["Overlay draws fake login screen over banking app (T1417.002)",
                  "Accessibility service captures input / auto-clicks (T1417)",
                  "SMS access intercepts OTPs (T1411 / T1582)"],
        "attack_ids": ["T1417", "T1411"],
        "severity": "CRITICAL",
        "effect": {"type": "critical"},
        "explanation": "SMS + accessibility + overlay together are the classic Android banking-trojan toolkit: "
                       "fake screens, captured input and intercepted OTPs.",
        "breaks_with": ["ACT_REMOVE_HIGH_PRIV", "ACT_UNINSTALL_APP"],
    },
    {
        "id": "CH_UNRECOVERABLE",
        "name": "Unrecoverable compromise",
        "condition": {"all": [{"finding": "DEV_NO_BACKUP"}, {"finding": "DEV_NO_AUTO_UPDATES"},
                              {"finding": "DEV_NO_DISK_ENCRYPTION"}]},
        "steps": ["Unpatched vulnerability exploited (no auto-updates)", "Ransomware encrypts / thief reads data (T1486)",
                  "No backup - data cannot be recovered"],
        "attack_ids": ["T1486"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "device", "tier": "HIGH"},
        "explanation": "No backups, no automatic patching and no encryption means one incident leads to permanent "
                       "data loss or exposure.",
        "breaks_with": ["ACT_BACKUP", "ACT_AUTO_UPDATES", "ACT_DISK_ENCRYPTION"],
    },
    {
        "id": "CH_INDIA_PAYMENT_SCAM",
        "name": "Payment-fraud lure",
        "condition": {"all": [{"any": [{"finding": "EMAIL_IN_UPI_COLLECT"}, {"finding": "EMAIL_IN_KYC"}]},
                              {"any": [{"finding": "EMAIL_EMBEDDED_URL_HIGH"}, {"finding": "EMAIL_EMBEDDED_URL_RISK"},
                                       {"finding": "EMAIL_CALLBACK_NUMBER"}, {"finding": "EMAIL_FINANCIAL_REQUEST"}]}]},
        "steps": ["KYC / UPI pretext message (T1566)", "Victim directed to link or phone number",
                  "Victim approves collect request / shares PIN-OTP (T1656 impersonation)"],
        "attack_ids": ["T1566", "T1656"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "email", "tier": "HIGH"},
        "explanation": "A KYC/UPI pretext combined with a payment request, call-back number or risky link is the "
                       "standard Indian payment-fraud script.",
        "breaks_with": ["ACT_REPORT_INDIA_SCAM", "ACT_REPORT_PHISHING"],
    },
    {
        "id": "CH_CREDENTIAL_STUFFING",
        "name": "Credential stuffing exposure",
        "condition": {"all": [{"any": [{"finding": "PWD_REUSED"}, {"finding": "PWD_COMMON"}, {"finding": "PWD_PWNED"}]},
                              {"finding": "DEV_NO_MFA"}]},
        "steps": ["Password exposed in public breach or wordlist replay (T1110.004)",
                  "No MFA leaves valid account takeover barrier-free (T1078)"],
        "attack_ids": ["T1110.004", "T1078"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "password", "tier": "HIGH"},
        "explanation": "A reused or common password combined with no multi-factor authentication creates direct exposure "
                       "to automated credential stuffing attacks, even without an active phishing lure.",
        "breaks_with": ["ACT_ENABLE_MFA", "ACT_UNIQUE_PASSWORDS", "ACT_LONG_PASSWORD"],
    },
    {
        "id": "CH_COERCION_SCAM",
        "name": "Coercive digital arrest / extortion",
        "condition": {"all": [{"finding": "EMAIL_IN_DIGITAL_ARREST"},
                              {"any": [{"finding": "EMAIL_FINANCIAL_REQUEST"}, {"finding": "EMAIL_URGENCY"},
                                       {"finding": "EMAIL_IN_AADHAAR_PAN"}]}]},
        "steps": ["Law enforcement / agency impersonation (T1656)",
                  "Coercive video-call / arrest intimidation threat (T1566)",
                  "Victim pressured into urgent financial transfer"],
        "attack_ids": ["T1656", "T1566"],
        "severity": "HIGH",
        "effect": {"type": "module_tier", "module": "email", "tier": "HIGH"},
        "explanation": "Digital arrest threats and government-agency impersonation with urgent financial demands form "
                       "a high-pressure extortion scam aimed at immediate funds transfer.",
        "breaks_with": ["ACT_REPORT_INDIA_SCAM", "ACT_REPORT_PHISHING"],
    },
]

