"""Lexical / structural URL feature extraction (shared by URL rules and URL ML model).

The URL is NEVER fetched or resolved - everything is computed from the string.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit

from utils.common import WORDLIST_DIR, levenshtein, load_wordlist

MULTI_PART_SUFFIXES = {
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in", "firm.in", "gen.in", "ind.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "com.cn",
    "com.mx", "com.tr", "co.za", "com.sg", "com.my", "com.pk", "com.ng", "co.id", "com.ar", "com.vn", "com.hk",
    "co.kr", "com.ua", "com.ru", "com.co", "com.pe", "com.ph", "com.bd", "com.eg", "com.sa", "co.il", "org.br",
    "net.br", "gov.br", "edu.au", "gov.au", "000webhostapp.com", "blogspot.com", "github.io", "herokuapp.com",
    "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "weebly.com", "wixsite.com", "appspot.com",
}
SENSITIVE_KEYWORDS = ["login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account",
                      "update", "banking", "confirm", "password", "wallet", "kyc", "webscr", "ebayisapi",
                      "unlock", "suspend", "billing", "payment", "authenticate", "recover", "validate", "otp"]
SPECIAL_CHARS = set("@~!$%^*()+=[]{}|\\;'\",<>`")
DIGIT_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})

FEATURE_NAMES = [
    "url_length", "num_dots", "num_subdomains", "num_special_chars", "has_ip", "has_https",
    "suspicious_tld", "has_at", "num_hyphens", "digit_ratio", "domain_length", "path_length",
    "is_shortener", "has_punycode", "brand_lookalike", "brand_in_subdomain_or_path",
    "num_sensitive_keywords", "has_port", "num_query_params", "path_depth", "double_slash_redirect",
    "domain_entropy",
]
FEATURE_LABELS = {
    "url_length": "URL length",
    "num_dots": "Number of dots",
    "num_subdomains": "Number of subdomains",
    "num_special_chars": "Special characters in URL",
    "has_ip": "IP address used as host",
    "has_https": "HTTPS scheme",
    "suspicious_tld": "Suspicious top-level domain",
    "has_at": "'@' symbol in URL",
    "num_hyphens": "Hyphens in URL",
    "digit_ratio": "Proportion of digits in domain",
    "domain_length": "Domain length",
    "path_length": "Path length",
    "is_shortener": "URL shortener",
    "has_punycode": "Punycode / IDN domain",
    "brand_lookalike": "Brand look-alike domain",
    "brand_in_subdomain_or_path": "Brand name outside the real domain",
    "num_sensitive_keywords": "Login/verify-type keywords",
    "has_port": "Explicit port number",
    "num_query_params": "Number of query parameters",
    "path_depth": "Path depth",
    "double_slash_redirect": "'//' redirect inside path",
    "domain_entropy": "Randomness of domain name",
}


@lru_cache(maxsize=1)
def brands() -> dict:
    data = json.loads((WORDLIST_DIR / "brands.json").read_text())
    data.pop("_comment", None)
    return data


@lru_cache(maxsize=1)
def suspicious_tlds() -> frozenset:
    return frozenset(load_wordlist("suspicious_tlds.txt"))


@lru_cache(maxsize=1)
def shorteners() -> frozenset:
    return frozenset(load_wordlist("url_shorteners.txt"))


def normalize_url(url: str) -> str:
    url = url.strip().strip("<>\"'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url  # scheme-less input: assume plain http (we cannot know it is https)
    return url


def parse(url: str) -> dict:
    url = normalize_url(url)
    parts = urlsplit(url)
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
    host, port = netloc, None
    if host.startswith("["):
        host = host[1:host.find("]")]
    elif ":" in host:
        host, _, port = host.rpartition(":")
    host = host.lower().rstrip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host):  # hex / integer-encoded IPs
            is_ip = True
    labels = host.split(".") if host else []
    if is_ip or len(labels) < 2:
        registered, suffix, sub = host, "", []
    else:
        last2 = ".".join(labels[-2:])
        if last2 in MULTI_PART_SUFFIXES and len(labels) >= 3:
            registered = ".".join(labels[-3:])
            suffix = last2
            sub = labels[:-3]
        else:
            registered = last2
            suffix = labels[-1]
            sub = labels[:-2]
    sub = [s for s in sub if s != "www"] if sub and sub[0] == "www" else sub
    return {
        "url": url, "scheme": parts.scheme.lower(), "host": host, "port": port, "userinfo": userinfo,
        "path": parts.path or "", "query": parts.query or "", "is_ip": is_ip,
        "registered_domain": registered, "suffix": suffix, "tld": (suffix.split(".")[-1] if suffix else ""),
        "subdomains": sub,
    }


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def brand_analysis(p: dict) -> dict:
    """Detect look-alike domains (edit distance / digit swaps) and brand names used outside the real domain."""
    reg = p["registered_domain"]
    core = reg.split(".")[0] if reg else ""
    tokens = re.split(r"[-_.]", core)
    lookalike, lookalike_brand, misplaced, misplaced_brand = False, None, False, None
    official = {d for ds in brands().values() for d in ds}
    if reg in official or p["is_ip"]:
        return {"lookalike": False, "lookalike_brand": None, "misplaced": False, "misplaced_brand": None}
    for brand, domains in brands().items():
        if len(brand) < 4:
            # very short brands (sbi) only via exact token match in domain -> misplaced brand
            if brand in tokens and reg not in domains:
                misplaced, misplaced_brand = True, brand
            continue
        for tok in tokens + [core]:
            if not tok:
                continue
            swapped = tok.translate(DIGIT_SWAPS)
            if tok == brand:
                if reg not in domains:
                    misplaced, misplaced_brand = True, brand  # e.g. paypal-secure.com
                continue
            if swapped == brand and tok != brand:
                lookalike, lookalike_brand = True, brand  # paypa1
            elif len(tok) >= 4 and abs(len(tok) - len(brand)) <= 2:
                d = levenshtein(swapped, brand, max_dist=2)
                if 0 < d <= (1 if len(brand) <= 5 else 2):
                    lookalike, lookalike_brand = True, brand
            if brand in tok and tok != brand and reg not in domains:
                misplaced, misplaced_brand = True, brand  # paypalsecure.com
    rest = (".".join(p["subdomains"]) + " " + p["path"] + " " + p["query"]).lower()
    for brand, domains in brands().items():
        if len(brand) >= 4 and brand in rest and reg not in domains:
            misplaced, misplaced_brand = True, misplaced_brand or brand
    return {"lookalike": lookalike, "lookalike_brand": lookalike_brand, "misplaced": misplaced,
            "misplaced_brand": misplaced_brand}


def extract_features(url: str) -> dict:
    p = parse(url)
    u = p["url"]
    host = p["host"]
    b = brand_analysis(p)
    lower = u.lower()
    domain_digits = sum(ch.isdigit() for ch in host)
    path = p["path"]
    # "http://x.com" and "http://x.com/" (or "/feed" and "/feed/") are the same resource: ignore a trailing slash.
    # Without this, datasets that store bare homepages without "/" teach the model that a lone "/" means phishing.
    norm_path = path.rstrip("/")
    feats = {
        "url_length": len(u.rstrip("/")),
        "num_dots": u.count("."),
        "num_subdomains": len(p["subdomains"]),
        "num_special_chars": sum(ch in SPECIAL_CHARS for ch in u),
        "has_ip": int(p["is_ip"]),
        "has_https": int(p["scheme"] == "https"),
        "suspicious_tld": int(p["tld"] in suspicious_tlds()),
        "has_at": int("@" in u),
        "num_hyphens": u.count("-"),
        "digit_ratio": round(domain_digits / max(len(host), 1), 4),
        "domain_length": len(host),
        "path_length": len(norm_path) + (len(p["query"]) + 1 if p["query"] else 0),
        "is_shortener": int(host in shorteners() or p["registered_domain"] in shorteners()),
        "has_punycode": int("xn--" in host),
        "brand_lookalike": int(b["lookalike"]),
        "brand_in_subdomain_or_path": int(b["misplaced"]),
        "num_sensitive_keywords": sum(1 for k in SENSITIVE_KEYWORDS if k in lower),
        "has_port": int(p["port"] is not None and p["port"] not in ("80", "443")),
        "num_query_params": len([q for q in p["query"].split("&") if q]),
        "path_depth": len([s for s in path.split("/") if s]),
        "double_slash_redirect": int("//" in path),
        "domain_entropy": round(_entropy(p["registered_domain"].split(".")[0] if not p["is_ip"] else host), 4),
    }
    return {"features": feats, "parsed": p, "brand": b}


def feature_vector(url: str) -> list[float]:
    f = extract_features(url)["features"]
    return [float(f[n]) for n in FEATURE_NAMES]
