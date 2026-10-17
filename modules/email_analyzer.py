"""Module 2 - Phishing Email Analysis (hybrid: header rules + content rules + India rules + URL module + ML).

PRIVACY: the email text is analysed in memory; only finding IDs/scores leave this
module (evidence strings never quote the body).
"""
from __future__ import annotations

import email
import json
import re
from email import policy
from email.utils import getaddresses, parseaddr
from functools import lru_cache

from modules.url_scanner import scan_url
from utils.common import WORDLIST_DIR, make_finding, make_module_result, risk_level, rule_ml_disagree
from utils.feature_extraction import brands, parse, suspicious_tlds
from utils.fusion import fuse_module

MODULE = "email"
ACT = ["ACT_REPORT_PHISHING"]
ACT_IN = ["ACT_REPORT_INDIA_SCAM", "ACT_REPORT_PHISHING"]
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
BARE_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|in|net|org|info|xyz|top|tk|ml|ga|cf|gq|co|io|me|site|online|live|link|click|shop|support)(?:/[^\s<>\"')]*)?", re.I)
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "rediffmail.com", "aol.com",
            "protonmail.com", "proton.me", "yandex.com", "mail.com", "gmx.com", "icloud.com", "zoho.com"}
LOGIN_HINTS = ["login", "log-in", "signin", "sign-in", "verify", "verification", "account", "secure", "update",
               "kyc", "password", "webscr", "auth", "unlock", "confirm"]


@lru_cache(maxsize=1)
def _lexicons():
    gen = json.loads((WORDLIST_DIR / "email_lexicon.json").read_text(encoding="utf-8"))
    ind = json.loads((WORDLIST_DIR / "india_scam_lexicon.json").read_text(encoding="utf-8"))
    gen.pop("_comment", None)
    ind.pop("_comment", None)
    comp = lambda d: {k: {**v, "re": [re.compile(p, re.I | re.S) for p in v["patterns"]]} for k, v in d.items()}
    return comp(gen), comp(ind)


DANGEROUS_EXTS = {".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".iso", ".img", ".hta", ".wsf", ".ps1", ".jar", ".lnk", ".cpl"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz"}


def parse_email(raw: str | bytes) -> dict:
    """Parse a raw email (with or without headers) into headers + plain-text body + attachments."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    raw = raw.replace("\r\n", "\n")
    has_headers = bool(re.match(r"^(?:[A-Za-z-]+:.*\n)+", raw)) and re.search(r"^(from|subject|to|date|received|return-path|reply-to):",
                                                                              raw, re.I | re.M) is not None
    headers, subject, body = {}, "", raw
    attachments = []
    if has_headers:
        msg = email.message_from_string(raw, policy=policy.default)
        for k in ["From", "Reply-To", "Return-Path", "Subject", "To", "Authentication-Results", "Received-SPF", "Date", "Message-ID"]:
            v = msg.get_all(k)
            if v:
                headers[k] = " ".join(str(x) for x in v)
        subject = headers.get("Subject", "")
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    try:
                        sz = len(part.get_payload(decode=True) or b"")
                    except Exception:
                        sz = 0
                    attachments.append({
                        "filename": fn,
                        "content_type": part.get_content_type(),
                        "size": sz
                    })
                elif part.get_content_type() in ("text/plain", "text/html") and not part.is_attachment():
                    try:
                        parts.append(part.get_content())
                    except Exception:  # noqa: BLE001
                        parts.append(part.get_payload(decode=True).decode("utf-8", "ignore") if part.get_payload(decode=True) else "")
        else:
            try:
                parts.append(msg.get_content())
            except Exception:  # noqa: BLE001
                parts.append(msg.get_payload())
        body = "\n".join(str(p) for p in parts)
    text_body = re.sub(r"<[^>]+>", " ", body)
    hrefs = re.findall(r"href=[\"']([^\"']+)[\"']", body, re.I)
    return {"headers": headers, "subject": subject, "body": text_body, "hrefs": hrefs,
            "has_headers": has_headers, "attachments": attachments}


def attachment_findings(attachments: list[dict]) -> list[dict]:
    f = []
    for att in attachments:
        fn = (att.get("filename") or "").lower()
        parts = fn.split(".")
        exts = [f".{part}" for part in parts[1:]]
        is_dangerous = any(fn.endswith(ext) for ext in DANGEROUS_EXTS)
        is_double_ext = len(exts) >= 2 and any(ext in DANGEROUS_EXTS for ext in exts[-1:])

        if is_dangerous or is_double_ext:
            f.append(make_finding(
                "EMAIL_DANGEROUS_ATTACHMENT", MODULE, "Dangerous executable / script attachment", "HIGH", 35,
                f"Attachment '{att.get('filename')}' has dangerous extension ({att.get('content_type')})",
                attack_ids=["T1204.002", "T1566.001"], remediation_ids=ACT
            ))
        elif any(fn.endswith(ext) for ext in ARCHIVE_EXTS):
            f.append(make_finding(
                "EMAIL_ARCHIVE_ATTACHMENT", MODULE, "Compressed archive attachment", "MEDIUM", 8,
                f"Attachment '{att.get('filename')}' is an archive file that may contain concealed scripts or malware",
                attack_ids=["T1566.001"], remediation_ids=ACT
            ))
    return f



def extract_urls(text: str, hrefs=()) -> list[str]:
    urls = list(hrefs) + URL_RE.findall(text)
    if not urls:
        urls = [m.group(0) for m in BARE_DOMAIN_RE.finditer(text) if "@" not in text[max(0, m.start() - 1):m.start()]]
    out, seen = [], set()
    for u in urls:
        u = u.rstrip(".,;:!?)")
        if u.lower().startswith("mailto:"):
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:15]


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(" >") if "@" in addr else ""


def header_findings(h: dict) -> list[dict]:
    f = []
    if not h:
        return f
    name, addr = parseaddr(h.get("From", ""))
    from_dom = _domain(addr)
    from_reg = parse(from_dom)["registered_domain"] if from_dom else ""
    if h.get("Reply-To"):
        rt = [a for _, a in getaddresses([h["Reply-To"]])]
        rt_dom = {_domain(a) for a in rt if a}
        if from_dom and rt_dom and all(parse(d)["registered_domain"] != from_reg for d in rt_dom):
            f.append(make_finding("EMAIL_REPLYTO_MISMATCH", MODULE, "Reply-To differs from sender domain", "MEDIUM", 12,
                                  "Replies would go to a different domain than the sender", attack_ids=["T1566"],
                                  remediation_ids=ACT))
    if h.get("Return-Path") and from_reg:
        rp = _domain(parseaddr(h["Return-Path"])[1])
        if rp and parse(rp)["registered_domain"] != from_reg:
            f.append(make_finding("EMAIL_RETURN_PATH_MISMATCH", MODULE, "Return-Path domain differs from From domain",
                                  "LOW", 6, "Envelope sender and visible sender use different domains",
                                  attack_ids=["T1566"], remediation_ids=ACT))
    if from_dom:
        p = parse(from_dom)
        from utils.feature_extraction import brand_analysis
        b = brand_analysis(p)
        reasons = []
        if p["tld"] in suspicious_tlds():
            reasons.append(f"suspicious TLD .{p['tld']}")
        if b["lookalike"]:
            reasons.append(f"look-alike of '{b['lookalike_brand']}'")
        if b["misplaced"]:
            reasons.append(f"brand '{b['misplaced_brand']}' in a non-brand domain")
        if re.search(r"\d{3,}", p["registered_domain"]) or p["registered_domain"].count("-") >= 2:
            reasons.append("random-looking domain")
        if reasons:
            f.append(make_finding("EMAIL_SUSPICIOUS_SENDER_DOMAIN", MODULE, "Suspicious sender domain", "MEDIUM", 12,
                                  "; ".join(reasons), attack_ids=["T1566", "T1583.001"], remediation_ids=ACT))
        # display-name spoofing: display name mentions a brand whose official domain differs
        lname = re.sub(r"[^a-z0-9]", "", (name or "").lower())
        for brand, domains in brands().items():
            if len(brand) >= 3 and brand in lname and p["registered_domain"] not in domains:
                f.append(make_finding("EMAIL_DISPLAY_NAME_SPOOF", MODULE, "Display-name spoofing", "HIGH", 18,
                                      f"Display name claims '{brand}' but sender domain is {p['registered_domain']}"
                                      + (" (free webmail)" if p["registered_domain"] in FREEMAIL else ""),
                                      attack_ids=["T1566", "T1656"], remediation_ids=ACT))
                break
    auth = (h.get("Authentication-Results", "") + " " + h.get("Received-SPF", "")).lower()
    for mech, pts in (("spf", 8), ("dkim", 8), ("dmarc", 10)):
        m = re.search(mech + r"\s*=\s*(\w+)", auth) or (re.match(r"\s*(fail|softfail)", h.get("Received-SPF", "").lower()) if mech == "spf" else None)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror", "temperror"):
            f.append(make_finding(f"EMAIL_{mech.upper()}_FAIL", MODULE, f"{mech.upper()} check did not pass", "MEDIUM", pts,
                                  f"Authentication-Results: {mech}={m.group(1)}", attack_ids=["T1566"], remediation_ids=ACT))
    return f


def content_findings(text: str, use_india_rules: bool = True) -> list[dict]:
    gen, ind = _lexicons()
    f = []
    for key, d in gen.items():
        hits = sum(1 for r in d["re"] if r.search(text))
        if hits:
            f.append(make_finding(f"EMAIL_{key}", MODULE, d["title"], d["severity"], d["points"] + 2 * (hits - 1),
                                  f"{hits} matching cue(s)", attack_ids=d["attack_ids"], remediation_ids=ACT))
    if use_india_rules:
        for key, d in ind.items():
            hits = sum(1 for r in d["re"] if r.search(text))
            if hits:
                f.append(make_finding(f"EMAIL_IN_{key}", MODULE, d["title"], d["severity"], d["points"] + 2 * (hits - 1),
                                      f"{hits} India-specific scam cue(s)", attack_ids=d["attack_ids"], remediation_ids=ACT_IN))
    letters = [c for c in text if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / max(len(letters), 1)
    excl = text.count("!")
    if (caps > 0.3 and len(letters) > 40) or excl >= 4:
        f.append(make_finding("EMAIL_FORMATTING_ANOMALY", MODULE, "Formatting anomalies (excess capitals / exclamation marks)",
                              "LOW", 4, f"{caps:.0%} capitals, {excl} exclamation marks", attack_ids=["T1566"],
                              remediation_ids=ACT))
    return f


def analyze_email(raw: str | bytes, use_ml: bool = True, use_india_rules: bool = True, scan_urls: bool = True,
                  explain: bool = True, use_url_ml: bool = True) -> dict:
    """use_ml toggles the email-text model; use_url_ml toggles the URL model used on embedded links."""
    if not raw or not str(raw).strip():
        raise ValueError("Empty email")
    pe = parse_email(raw)
    text = (pe["subject"] + "\n" + pe["body"]).strip()
    findings = header_findings(pe["headers"]) + content_findings(text, use_india_rules) + attachment_findings(pe.get("attachments", []))

    # Layer 3: embedded URLs through Module 3
    urls = extract_urls(pe["body"], pe["hrefs"])
    worst = None
    url_summ = []
    if scan_urls:
        for u in urls:
            try:
                r = scan_url(u, use_ml=use_url_ml, explain=False)
            except ValueError:
                continue
            url_summ.append({"domain": r["extra"]["registered_domain"], "score": r["score"], "risk": r["risk_level"]})
            if worst is None or r["score"] < worst[1]["score"]:
                worst = (u, r)
    if worst is not None and worst[1]["score"] < 80:
        u, r = worst
        sev = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MODERATE": "MEDIUM"}[r["risk_level"]]
        fid = "EMAIL_EMBEDDED_URL_HIGH" if r["score"] < 60 else "EMAIL_EMBEDDED_URL_RISK"
        findings.append(make_finding(fid, MODULE, f"Embedded link scored {r['risk_level']} by URL scanner", sev,
                                     0.45 * (100 - r["score"]),
                                     f"Worst link domain {r['extra']['registered_domain']} scored {r['score']:.0f}/100",
                                     attack_ids=["T1566.002"], remediation_ids=["ACT_AVOID_URL", "ACT_REPORT_PHISHING"]))
    if urls and any(any(k in u.lower() for k in LOGIN_HINTS) for u in urls):
        findings.append(make_finding("EMAIL_LOGIN_LINK", MODULE, "Link points to a login/verify-style page", "MEDIUM", 8,
                                     "Embedded link path contains login/verify/account keywords",
                                     attack_ids=["T1566.002"], remediation_ids=["ACT_AVOID_URL", "ACT_REPORT_PHISHING"]))

    raw_def = sum(x["points_lost"] for x in findings)
    k = 100.0 / raw_def if raw_def > 100 else 1.0
    r_score = 100.0 - min(100.0, raw_def)

    ml = None
    if use_ml:
        try:
            from ml.phishing_model import feature_label, predict_email
            ml = predict_email("Subject: " + pe["subject"] + "\n" + pe["body"], explain=explain)
        except FileNotFoundError:
            ml = None
    r_def = min(100.0, raw_def)
    if ml is not None:
        rule_part, ml_part = fuse_module(MODULE, r_def, ml["probability"] * 100)
    else:
        rule_part, ml_part = r_def, 0.0
    rk = (rule_part / r_def) if r_def > 0 else 0.0
    out = []
    for x in findings:
        y = dict(x)
        y["points_lost"] = x["points_lost"] * k * rk
        out.append(y)
    agreement, uncertain = None, False
    if ml is not None:
        prob = ml["probability"]
        sev = "HIGH" if prob >= 0.9 else "MEDIUM" if prob >= 0.7 else "LOW" if prob >= 0.5 else "INFO"
        top = ", ".join(feature_label(n) for n, v in ml["shap_top"] if v > 0)[:200] or "no strong risk features"
        out.append(make_finding("EMAIL_ML_PHISHING", MODULE,
                                "ML model: text resembles phishing emails" if prob >= 0.5 else "ML model: text resembles legitimate emails",
                                sev, ml_part, f"{ml['model_name']} probability {prob:.2f}"
                                + (f"; SHAP top cues: {top}" if ml["shap_top"] else ""),
                                source="ml", attack_ids=["T1566"], remediation_ids=ACT))
        ml_score = 100 * (1 - prob)
        uncertain = rule_ml_disagree(r_score, ml_score)
        agreement = not uncertain
        ml = dict(ml)
        ml["score"] = ml_score
    expl = [x["title"] for x in sorted(out, key=lambda z: -z["points_lost"]) if x["points_lost"] > 0.5]
    extra = {"rule_score": round(r_score, 2), "n_urls": len(urls), "urls": url_summ,
             "header_present": pe["has_headers"], "india_rules": use_india_rules,
             "phishing_probability": None if ml is None else round(ml["probability"], 4),
             "rule_risk": risk_level(r_score), "headers": pe["headers"],
             "attachments": pe.get("attachments", []), "subject": pe.get("subject", "")}
    return make_module_result(MODULE, out, ml=ml, rule_ml_agreement=agreement, uncertain=uncertain,
                              explanations=expl, extra=extra)

