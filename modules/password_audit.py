"""Module 1 - Password Security Audit (rule-based).

PRIVACY: the password is analysed in memory only.  It is never written to disk,
logged, returned, or embedded in any finding/evidence string (evidence strings
describe *patterns*, never the matched characters).
"""
from __future__ import annotations

import hashlib
import math
import re
import urllib.error
import urllib.request
from functools import lru_cache

from utils.common import load_wordlist, make_finding, make_module_result

MODULE = "password"
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s", "7": "t", "!": "i"})
LEET_MAP_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s", "7": "t", "!": "i"})
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "qazwsxedc"]
YEAR_RE = re.compile(r"(19[4-9]\d|20[0-3]\d)")
NAME_DIGITS_RE = re.compile(r"^[A-Za-z]{3,}[._-]?\d{1,4}[^A-Za-z0-9]{0,2}$")
WORD_THEN_DIGITS_RE = re.compile(r"^[A-Za-z]{3,}[@#!$._-]?\d{1,4}[@#!$._-]?$")

ACT_PW = ["ACT_LONG_PASSWORD", "ACT_ENABLE_MFA"]


def check_hibp_pwned(pw: str, timeout: float = 3.0) -> int:
    """Check breach count using HaveIBeenPwned k-Anonymity API.

    Zero-knowledge privacy: Only the first 5 characters of the SHA-1 hash
    are transmitted over HTTPS. The rest of the hash is matched locally.
    Returns the count of data breaches this password appeared in (0 if none or offline).
    """
    if not pw:
        return 0
    try:
        sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberGuardian-Risk-Scanner"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            for line in text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    return int(parts[1])
    except Exception:
        return 0
    return 0



@lru_cache(maxsize=1)
def _common() -> frozenset:
    return frozenset(w.lower() for w in load_wordlist("common_passwords.txt"))


@lru_cache(maxsize=1)
def _words() -> frozenset:
    words = {w.lower() for w in load_wordlist("english_words.txt") if len(w) >= 4 and w.isalpha()}
    words |= {w.lower() for w in load_wordlist("names.txt") if len(w) >= 4}
    # common passwords that are pure words also count as dictionary words
    words |= {w for w in _common() if len(w) >= 5 and w.isalpha()}
    return frozenset(words)


def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 33
    return size or 1


def _find_words(pw: str) -> list[tuple[int, int]]:
    """Return spans of dictionary/name words (len>=4) after leet normalisation."""
    spans = []
    words = _words()
    for norm in {pw.lower().translate(LEET_MAP), pw.lower().translate(LEET_MAP_L)}:
        n = len(norm)
        i = 0
        while i < n:
            best = 0
            for j in range(min(n, i + 20), i + 3, -1):
                if norm[i:j] in words:
                    best = j - i
                    break
            if best:
                spans.append((i, i + best))
                i += best
            else:
                i += 1
    return _merge(spans)


def _find_sequences(pw: str, min_len: int = 3) -> list[tuple[int, int]]:
    low = pw.lower()
    spans = []
    i = 0
    while i < len(low) - min_len + 1:
        found = 0
        for seq in SEQUENCES:
            for s in (seq, seq[::-1]):
                for L in range(len(low) - i, min_len - 1, -1):
                    if low[i:i + L] in s:
                        found = max(found, L)
                        break
        if found >= min_len:
            spans.append((i, i + found))
            i += found
        else:
            i += 1
    return spans


def _find_repeats(pw: str) -> list[tuple[int, int]]:
    spans = [(m.start(), m.end()) for m in re.finditer(r"(.)\1{2,}", pw)]
    spans += [(m.start(), m.end()) for m in re.finditer(r"(.{2,4})\1{1,}", pw) if len(m.group(0)) >= 4]
    return _merge(spans)


def _merge(spans):
    spans = sorted(spans)
    out = []
    for s, e in spans:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def estimate_entropy(pw: str) -> dict:
    """Naive bits = len * log2(charset); effective bits apply pattern penalties.

    Characters covered by a detected pattern (dictionary word, sequence, repeat,
    year) are replaced by the (much smaller) entropy of guessing that pattern.
    """
    cs = charset_size(pw)
    per_char = math.log2(cs)
    naive = len(pw) * per_char
    covered = [False] * len(pw)
    pattern_bits = 0.0
    n_words = max(len(_words()), 2)
    for s, e in _find_words(pw):
        pattern_bits += math.log2(n_words) + (1 if pw[s:e] != pw[s:e].lower() else 0)
        for k in range(s, e):
            covered[k] = True
    for s, e in _find_sequences(pw):
        if not all(covered[s:e]):
            pattern_bits += math.log2(len(SEQUENCES) * 2 * 26) + math.log2(max(e - s, 2))
            for k in range(s, e):
                covered[k] = True
    for s, e in _find_repeats(pw):
        if not all(covered[s:e]):
            pattern_bits += per_char + math.log2(max(e - s, 2))
            for k in range(s, e):
                covered[k] = True
    for m in YEAR_RE.finditer(pw):
        if not all(covered[m.start():m.end()]):
            pattern_bits += math.log2(100)
            for k in range(m.start(), m.end()):
                covered[k] = True
    uncovered = sum(1 for c in covered if not c)
    effective = uncovered * per_char + pattern_bits
    return {"naive_bits": naive, "effective_bits": min(naive, effective), "charset": cs}


def audit_password(password: str, reused: bool = False, check_hibp: bool = False) -> dict:
    """Audit a password.  Returns a ModuleResult; the password itself is never included."""
    if not password:
        raise ValueError("Empty password")
    pw = password
    f = []
    L = len(pw)
    checks = {
        "length": L >= 12,
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "digits": bool(re.search(r"\d", pw)),
        "special": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }
    if L < 8:
        f.append(make_finding("PWD_TOO_SHORT", MODULE, "Password too short", "HIGH", 25,
                              f"Length {L} characters (< 8)", attack_ids=["T1110"], remediation_ids=ACT_PW))
    elif L < 12:
        f.append(make_finding("PWD_SHORT", MODULE, "Password shorter than recommended", "MEDIUM", 10,
                              f"Length {L} characters (< 12 recommended)", attack_ids=["T1110"], remediation_ids=["ACT_LONG_PASSWORD"]))
    for key, fid, title in [("uppercase", "PWD_NO_UPPER", "No uppercase letters"),
                            ("lowercase", "PWD_NO_LOWER", "No lowercase letters"),
                            ("digits", "PWD_NO_DIGIT", "No digits"),
                            ("special", "PWD_NO_SPECIAL", "No special characters")]:
        if not checks[key]:
            f.append(make_finding(fid, MODULE, title, "LOW", 5 if key == "special" else 4,
                                  f"Character class missing: {key}", attack_ids=["T1110"], remediation_ids=["ACT_LONG_PASSWORD"]))

    low = pw.lower()
    is_common = low in _common() or low.translate(LEET_MAP) in _common() or low.translate(LEET_MAP_L) in _common()
    if is_common:
        f.append(make_finding("PWD_COMMON", MODULE, "Password appears in common-password list", "HIGH", 45,
                              "Found in a list of the 10,000 most common passwords (incl. leetspeak variants)",
                              attack_ids=["T1110.001", "T1110.003"], remediation_ids=ACT_PW))

    breach_count = 0
    if check_hibp:
        breach_count = check_hibp_pwned(pw)
        if breach_count > 0:
            pts = 45 if breach_count >= 1000 else 30
            f.append(make_finding("PWD_PWNED", MODULE, "Password exposed in public data breaches", "HIGH", pts,
                                  f"Exposed in {breach_count:,} public data breaches (verified via k-anonymity API)",
                                  attack_ids=["T1110.004", "T1078"],
                                  remediation_ids=["ACT_UNIQUE_PASSWORDS", "ACT_ENABLE_MFA", "ACT_LONG_PASSWORD"]))

    name_digits = bool(NAME_DIGITS_RE.match(pw) or WORD_THEN_DIGITS_RE.match(pw)) and not is_common
    words = _find_words(pw)
    # A word inside a Name+digits password is already covered by PWD_NAME_DIGITS (avoid double counting).
    if words and not is_common and not name_digits:
        covered = sum(e - s for s, e in words)
        f.append(make_finding("PWD_DICTIONARY_WORD", MODULE, "Contains a dictionary word or common name", "MEDIUM", 12,
                              f"{len(words)} dictionary/name segment(s) covering {covered} of {L} characters (leetspeak normalised)",
                              attack_ids=["T1110.001"], remediation_ids=["ACT_LONG_PASSWORD"]))
    if _find_repeats(pw):
        f.append(make_finding("PWD_REPEATED_CHARS", MODULE, "Repeated characters or blocks", "MEDIUM", 8,
                              "Contains a run of 3+ identical characters or a repeated block", attack_ids=["T1110"],
                              remediation_ids=["ACT_LONG_PASSWORD"]))
    if _find_sequences(pw):
        f.append(make_finding("PWD_SEQUENTIAL", MODULE, "Sequential / keyboard pattern", "MEDIUM", 10,
                              "Contains an alphabetical, numeric or keyboard sequence of 3+ characters",
                              attack_ids=["T1110"], remediation_ids=["ACT_LONG_PASSWORD"]))
    if name_digits:
        f.append(make_finding("PWD_NAME_DIGITS", MODULE, "Name/word + digits pattern", "HIGH", 15,
                              "Structure is letters followed by a short number (e.g. Name123) - the first pattern attackers try",
                              attack_ids=["T1110.001"], remediation_ids=ACT_PW))
    if YEAR_RE.search(pw):
        f.append(make_finding("PWD_YEAR_PATTERN", MODULE, "Contains a year", "MEDIUM", 6,
                              "Contains a 4-digit year (birth/anniversary years are commonly guessed)",
                              attack_ids=["T1110"], remediation_ids=["ACT_LONG_PASSWORD"]))
    ent = estimate_entropy(pw)
    eb = ent["effective_bits"]
    if eb < 40:
        f.append(make_finding("PWD_LOW_ENTROPY", MODULE, "Low password entropy", "HIGH", 20,
                              f"Estimated effective entropy {eb:.0f} bits (< 40) after pattern penalties",
                              attack_ids=["T1110"], remediation_ids=ACT_PW))
    elif eb < 60:
        f.append(make_finding("PWD_MODERATE_ENTROPY", MODULE, "Moderate password entropy", "MEDIUM", 8,
                              f"Estimated effective entropy {eb:.0f} bits (< 60)", attack_ids=["T1110"],
                              remediation_ids=["ACT_LONG_PASSWORD"]))
    if reused:
        f.append(make_finding("PWD_REUSED", MODULE, "Password reused on other sites", "HIGH", 25,
                              "User indicated this password is used elsewhere (credential-stuffing risk)",
                              attack_ids=["T1110.004", "T1078"], remediation_ids=["ACT_UNIQUE_PASSWORDS", "ACT_ENABLE_MFA"]))

    entropy_label = "Low" if eb < 40 else ("Moderate" if eb < 60 else "High")
    extra = {"checks": checks, "entropy_bits": round(eb, 1), "naive_bits": round(ent["naive_bits"], 1),
             "entropy_label": entropy_label, "length": L, "breach_count": breach_count}
    return make_module_result(MODULE, f, extra=extra)


def summary_line(result: dict) -> str:
    c = result["extra"]["checks"]
    tick = lambda b: "✓" if b else "✗"
    ids = {x["id"] for x in result["findings"]}
    pat = "⚠ (name + digits)" if "PWD_NAME_DIGITS" in ids else ("⚠ (pattern found)" if ids & {"PWD_SEQUENTIAL", "PWD_DICTIONARY_WORD", "PWD_COMMON", "PWD_REPEATED_CHARS"} else "✓ none")
    breach = f"\nData Breach: ⚠ {result['extra']['breach_count']:,} known leaks" if result["extra"].get("breach_count", 0) > 0 else ""
    return (f"Length {tick(c['length'])} · Upper {tick(c['uppercase'])} · Lower {tick(c['lowercase'])} · "
            f"Numbers {tick(c['digits'])} · Special {tick(c['special'])}\n"
            f"Pattern: {pat} · Entropy: {result['extra']['entropy_label']}{breach}")

