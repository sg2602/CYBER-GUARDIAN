"""Module 3 - Website / URL Security Assessment (hybrid: rules + ML + SHAP).

CyberGuardian *estimates URL-based security risk using structural, domain and
ML-based indicators*.  The URL is never fetched, resolved or visited.
"""
from __future__ import annotations

from utils.common import make_finding, make_module_result, rule_ml_disagree
from utils.feature_extraction import FEATURE_LABELS, brands, extract_features
from utils.fusion import fuse_module

MODULE = "url"
ACT = ["ACT_AVOID_URL"]
ALLOWLIST_ML_DAMPING = 0.3  # official brand domains: ML estimate down-weighted (allow-list)


def is_official_domain(registered_domain: str) -> bool:
    return any(registered_domain in ds for ds in brands().values())


def rule_findings(url: str) -> tuple[list[dict], dict]:
    info = extract_features(url)
    x, p, b = info["features"], info["parsed"], info["brand"]
    f = []

    def add(fid, title, sev, pts, ev, attack=("T1566.002",)):
        f.append(make_finding(fid, MODULE, title, sev, pts, ev, attack_ids=list(attack), remediation_ids=ACT))

    if not x["has_https"]:
        add("URL_NO_HTTPS", "No HTTPS (unencrypted connection)", "MEDIUM", 10, f"Scheme is '{p['scheme']}'")
    if x["has_ip"]:
        add("URL_IP_HOST", "Raw IP address used instead of a domain", "HIGH", 25, "Host is an IP address")
    if x["has_at"]:
        add("URL_AT_SYMBOL", "'@' symbol in URL (can hide real destination)", "HIGH", 20,
            "Text before '@' is ignored by browsers")
    if x["suspicious_tld"]:
        add("URL_SUSPICIOUS_TLD", "Suspicious top-level domain", "MEDIUM", 12, f"TLD .{p['tld']} is frequently abused")
    if x["url_length"] > 75:
        add("URL_LONG", "Unusually long URL", "LOW", 5, f"{x['url_length']} characters (> 75)")
    if x["num_subdomains"] >= 3:
        add("URL_MANY_SUBDOMAINS", "Many subdomain levels", "MEDIUM", 10, f"{x['num_subdomains']} subdomain levels")
    if x["num_hyphens"] >= 3 or p["registered_domain"].count("-") >= 2:
        add("URL_MANY_HYPHENS", "Many hyphens", "LOW", 6, f"{x['num_hyphens']} hyphens")
    if x["digit_ratio"] > 0.2 and not x["has_ip"]:
        add("URL_HIGH_DIGIT_RATIO", "Many digits in domain", "LOW", 5, f"{x['digit_ratio']:.0%} of host characters are digits")
    if x["is_shortener"]:
        add("URL_SHORTENER", "URL shortener hides the real destination", "MEDIUM", 15, f"Shortener domain {p['registered_domain']}")
    if x["has_punycode"]:
        add("URL_PUNYCODE", "Punycode / internationalised domain (possible homograph)", "HIGH", 20, "Host contains 'xn--'")
    if x["brand_lookalike"]:
        add("URL_BRAND_LOOKALIKE", "Look-alike of a well-known brand domain", "HIGH", 25,
            f"Domain resembles '{b['lookalike_brand']}' (edit distance / digit-for-letter swap)", attack=("T1566.002", "T1583.001"))
    if x["brand_in_subdomain_or_path"] and not x["brand_lookalike"]:
        add("URL_BRAND_MISPLACED", "Brand name used outside the brand's real domain", "MEDIUM", 15,
            f"'{b['misplaced_brand']}' appears but registered domain is {p['registered_domain']}", attack=("T1566.002", "T1583.001"))
    if x["num_sensitive_keywords"] >= 1:
        add("URL_SENSITIVE_KEYWORDS", "Login / verify / account keywords", "MEDIUM", 6 + 4 * min(x["num_sensitive_keywords"], 3),
            f"{x['num_sensitive_keywords']} credential-related keyword(s) in URL")
    if x["has_port"]:
        add("URL_NONSTANDARD_PORT", "Non-standard port", "MEDIUM", 8, f"Port {p['port']}")
    if x["double_slash_redirect"]:
        add("URL_DOUBLE_SLASH_REDIRECT", "'//' inside path (possible redirect)", "LOW", 6, "Path contains '//'")
    if x["num_special_chars"] >= 4:
        add("URL_MANY_SPECIAL_CHARS", "Many special characters", "LOW", 5, f"{x['num_special_chars']} special characters")
    if x["domain_entropy"] > 3.6 and x["domain_length"] > 15 and not x["has_ip"]:
        add("URL_RANDOM_DOMAIN", "Random-looking domain name", "LOW", 6, f"Domain character entropy {x['domain_entropy']:.2f}")
    return f, info


def rule_score(url: str) -> float:
    f, _ = rule_findings(url)
    return max(0.0, 100.0 - min(100.0, sum(x["points_lost"] for x in f)))


def scan_url(url: str, use_ml: bool = True, use_rules: bool = True, explain: bool = True) -> dict:
    if not url or not url.strip():
        raise ValueError("Empty URL")
    rf, info = rule_findings(url)
    if not use_rules:
        rf = []
    raw = sum(x["points_lost"] for x in rf)
    k = (100.0 / raw) if raw > 100 else 1.0
    r_deficit = min(100.0, raw)
    r_score = 100.0 - r_deficit

    ml = None
    if use_ml:
        try:
            from ml.url_model import predict_url
            ml = predict_url(url, explain=explain)
        except FileNotFoundError:
            ml = None
    findings = []
    agreement, uncertain = None, False
    official = is_official_domain(info["parsed"]["registered_domain"])
    if ml is not None:
        prob = ml["probability"]
        ml_score = 100.0 * (1 - prob)
        m_def = prob * 100 * (ALLOWLIST_ML_DAMPING if official else 1.0)
        if use_rules:
            rule_part, ml_part = fuse_module(MODULE, r_deficit, m_def)
        else:
            rule_part, ml_part = 0.0, m_def
    else:
        rule_part, ml_part = r_deficit, 0.0
    rk = (rule_part / r_deficit) if r_deficit > 0 else 0.0
    for x in rf:
        y = dict(x)
        y["points_lost"] = x["points_lost"] * k * rk
        findings.append(y)
    if ml is not None:
        sev = "HIGH" if prob >= 0.9 else "MEDIUM" if prob >= 0.7 else "LOW" if prob >= 0.5 else "INFO"
        top = ", ".join(FEATURE_LABELS.get(n, n) for n, v in ml["shap_top"] if v > 0)[:200] or "no strong risk features"
        title = "ML model: URL resembles known phishing URLs" if prob >= 0.5 else "ML model: URL resembles legitimate URLs"
        findings.append(make_finding("URL_ML_MALICIOUS", MODULE, title, sev, ml_part,
                                     f"{ml['model_name']} probability {prob:.2f}"
                                     + (f"; SHAP top risk features: {top}" if ml["shap_top"] else ""),
                                     source="ml", attack_ids=["T1566.002"], remediation_ids=ACT))
        if official:
            findings[-1]["evidence"] += " (official domain of a known brand - ML weight reduced by allow-list)"
        if use_rules:
            uncertain = rule_ml_disagree(r_score, ml_score) and not official
            agreement = not uncertain
        ml = dict(ml)
        ml["score"] = ml_score
    expl = [x["title"] for x in sorted(findings, key=lambda z: -z["points_lost"]) if x["points_lost"] > 0.5]
    res = make_module_result(MODULE, findings, ml=ml, rule_ml_agreement=agreement, uncertain=uncertain,
                             explanations=expl,
                             extra={"rule_score": round(r_score, 2), "features": info["features"],
                                    "registered_domain": info["parsed"]["registered_domain"],
                                    "official_domain": official,
                                    "checks": _checks(info)})
    return res


def _checks(info) -> dict:
    x = info["features"]
    return {
        "HTTPS": bool(x["has_https"]),
        "IP host": bool(x["has_ip"]),
        "Suspicious pattern": bool(x["has_at"] or x["double_slash_redirect"] or x["suspicious_tld"] or x["num_hyphens"] >= 3),
        "Homograph-like": bool(x["brand_lookalike"] or x["has_punycode"]),
        "Long URL": x["url_length"] > 75,
        "Domain anomaly": bool(x["brand_in_subdomain_or_path"] or x["brand_lookalike"] or x["digit_ratio"] > 0.2 or x["num_subdomains"] >= 3),
        "Shortener": bool(x["is_shortener"]),
    }
