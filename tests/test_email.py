from modules.email_analyzer import analyze_email, extract_urls, parse_email
from utils import demo_inputs as d


def ids(r):
    return {f["id"] for f in r["findings"]}


def test_demo_phish_flags():
    r = analyze_email(d.DEMO_EMAIL)
    assert r["risk_level"] in ("HIGH", "CRITICAL")
    assert {"EMAIL_IN_KYC", "EMAIL_REPLYTO_MISMATCH", "EMAIL_DISPLAY_NAME_SPOOF", "EMAIL_CREDENTIAL_REQUEST",
            "EMAIL_EMBEDDED_URL_HIGH", "EMAIL_LOGIN_LINK"} <= ids(r)
    assert r["ml"] is not None and 0 <= r["ml"]["probability"] <= 1


def test_legit_email_low():
    r = analyze_email(d.DEMO_LEGIT_EMAIL)
    assert r["risk_level"] in ("LOW", "MODERATE")
    assert not any(f["id"].startswith("EMAIL_IN_") for f in r["findings"])


def test_india_rules_toggle():
    txt = "To receive the cashback, enter your UPI PIN on the collect request now."
    assert "EMAIL_IN_UPI_COLLECT" in ids(analyze_email(txt, use_india_rules=True))
    assert not any(f.startswith("EMAIL_IN_") for f in ids(analyze_email(txt, use_india_rules=False)))


def test_auth_results_parsed():
    raw = ("From: Bank <alerts@bank-example.com>\nAuthentication-Results: mx.test; spf=fail; dkim=none; dmarc=fail\n"
           "Subject: hi\n\nhello")
    assert {"EMAIL_SPF_FAIL", "EMAIL_DKIM_FAIL", "EMAIL_DMARC_FAIL"} <= ids(analyze_email(raw, use_ml=False))


def test_parse_and_extract():
    pe = parse_email(d.DEMO_EMAIL)
    assert pe["has_headers"] and "KYC" in pe["subject"]
    assert extract_urls(pe["body"]) == ["http://sbi-kyc-update.xyz/login.php"]


def test_disagreement_flag_semantics():
    # rules see nothing, ML may or may not - flag must equal the documented rule
    from utils.common import rule_ml_disagree
    r = analyze_email(d.DEMO_LEGIT_EMAIL)
    assert r["uncertain"] == rule_ml_disagree(r["extra"]["rule_score"], r["ml"]["score"])


def test_dangerous_attachment_detected():
    raw_eml = (
        "From: HR Department <hr@company-update.com>\n"
        "Subject: Revised Benefits Document\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n\n"
        "Please review the attached document.\n"
        "--BOUNDARY\n"
        "Content-Type: application/octet-stream; name=\"benefits.pdf.exe\"\n"
        "Content-Disposition: attachment; filename=\"benefits.pdf.exe\"\n\n"
        "TVqQAAMAAAAEAAAA//8A\n"
        "--BOUNDARY--\n"
    )
    r = analyze_email(raw_eml, use_ml=False)
    assert "EMAIL_DANGEROUS_ATTACHMENT" in ids(r)
    assert len(r["extra"]["attachments"]) == 1
    assert r["extra"]["attachments"][0]["filename"] == "benefits.pdf.exe"


def test_archive_attachment_detected():
    raw_eml = (
        "From: Logistics <delivery@courier.com>\n"
        "Subject: Shipping Label Archive\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n\n"
        "Archive attached.\n"
        "--BOUNDARY\n"
        "Content-Type: application/zip; name=\"labels.zip\"\n"
        "Content-Disposition: attachment; filename=\"labels.zip\"\n\n"
        "UEsDBBQAAAAIA\n"
        "--BOUNDARY--\n"
    )
    r = analyze_email(raw_eml, use_ml=False)
    assert "EMAIL_ARCHIVE_ATTACHMENT" in ids(r)

