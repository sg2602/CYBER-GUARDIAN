import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from modules import device_audit, email_analyzer, password_audit, permission_audit, url_scanner  # noqa: E402
from utils import demo_inputs as demo  # noqa: E402
from utils import ui  # noqa: E402
from utils.feature_extraction import FEATURE_LABELS  # noqa: E402

ui.setup("Security Scanner")
st.title("🔍 Security Scanner")
st.caption("Assess each area; results appear immediately. Skipped modules are excluded and the score's coverage drops.")

tabs = st.tabs(["Password", "Email", "Website", "App Permissions", "Device"])


def show_ml(res, label_fn):
    if res.get("ml"):
        ml = res["ml"]
        st.markdown(f"**ML ({ml['model_name']})**: phishing probability **{ml['probability']:.0%}** · "
                    f"rule-based score {res['extra']['rule_score']:.0f} vs ML score {ml['score']:.0f}"
                    + (" → **disagreement**" if res.get("uncertain") else " → agree"))
        if ml.get("shap_top"):
            st.plotly_chart(ui.shap_bar(ml["shap_top"], label_fn), width="stretch")


def clear_button(module):
    if module in ui.results() and st.button("Clear / skip this module", key=f"clear_{module}"):
        ui.clear_result(module)
        st.rerun()


# ---------------- Password ----------------
with tabs[0]:
    st.subheader("Password Security Audit")
    st.info("🔒 Password inputs are processed locally and are never stored (not in the database, logs, session or reports).")
    with st.form("pw_form", clear_on_submit=True):
        pw = st.text_input("Password to check", type="password")
        c_opt1, c_opt2 = st.columns(2)
        reused = c_opt1.checkbox("I use this password elsewhere")
        check_hibp = c_opt2.checkbox("Check breach database (k-Anonymity API)", value=True,
                                     help="Zero-knowledge: Only a 5-char hash prefix is queried via HTTPS to check against 800M+ leaked passwords without revealing your password.")
        c1, c2 = st.columns(2)
        go_btn = c1.form_submit_button("Analyse password", type="primary")
        demo_btn = c2.form_submit_button("Use demo example (Samriddhi123)")
    if go_btn and pw:
        ui.set_result("password", password_audit.audit_password(pw, reused=reused, check_hibp=check_hibp))
    elif demo_btn:
        ui.set_result("password", password_audit.audit_password(demo.DEMO_PASSWORD))
    del pw  # do not keep the password around
    res = ui.results().get("password")
    if res:
        ui.module_header(res, "Password")
        if res["extra"].get("breach_count", 0) > 0:
            st.error(f"🚨 **Data Breach Warning**: This password appeared in **{res['extra']['breach_count']:,}** public data breaches! "
                     "Attackers possess this password in automated credential-stuffing dictionaries.")
        c = res["extra"]["checks"]
        t_fn = lambda b: "✓" if b else "✗"
        st.markdown(f"""
        <div class="cg-card" style="padding:12px 18px; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:12px; font-size:0.92rem; align-items:center;">
                <div><b>Checks:</b> Length {res['extra']['length']} {t_fn(c['length'])} &nbsp;·&nbsp; 
                     Upper {t_fn(c['uppercase'])} &nbsp;·&nbsp; 
                     Lower {t_fn(c['lowercase'])} &nbsp;·&nbsp; 
                     Digits {t_fn(c['digits'])} &nbsp;·&nbsp; 
                     Special {t_fn(c['special'])}</div>
                <div><b>Entropy:</b> {res['extra']['entropy_bits']} bits ({res['extra']['entropy_label']}) &nbsp;·&nbsp; 
                     <b>Risk:</b> {ui.badge(res['risk_level'])}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        ui.findings_table(res)
        clear_button("password")


# ---------------- Email ----------------
with tabs[1]:
    st.subheader("Phishing Email Analysis")
    st.caption("Upload a downloaded .eml message file or paste email text directly. Embedded links are scanned lexically without visiting.")

    email_mode = st.radio("Input method:", ["📁 Drag & Drop .eml File (Recommended)", "✍️ Copy-Paste Email Text"], horizontal=True)

    up_file = None
    txt_content = ""

    if "Drag & Drop" in email_mode:
        up_file = st.file_uploader("Upload .eml message file (e.g. Gmail: ⋮ > Download message)", type=["eml", "txt"], key="eml_upload")
        if up_file is not None:
            st.info(f"📁 Selected file: **{up_file.name}** ({up_file.size:,} bytes). Click 'Analyse email' to inspect.")
    else:
        c1, c2 = st.columns(2)
        c1.button("Load sample phishing email", on_click=lambda: st.session_state.update(email_text=demo.DEMO_EMAIL))
        c2.button("Load sample legitimate email", on_click=lambda: st.session_state.update(email_text=demo.DEMO_LEGIT_EMAIL))
        txt_content = st.text_area("Paste raw email or message body here:", key="email_text", height=200)

    india = st.checkbox("Use India-localized scam rules (C5)", value=True, key="india_rules_chk")
    if st.button("Analyse email", type="primary", key="btn_analyse_email"):
        raw_input = up_file.getvalue() if up_file is not None else txt_content
        if raw_input and str(raw_input).strip():
            ui.set_result("email", email_analyzer.analyze_email(raw_input, use_india_rules=india))
            st.rerun()
        else:
            st.warning("Please upload a .eml file or paste email text first.")

    res = ui.results().get("email")
    if res:
        ui.module_header(res, "Email")
        x = res["extra"]

        # Display inspected email headers
        if x.get("header_present") and x.get("headers"):
            h = x["headers"]
            with st.expander("📬 Inspected Email Headers & Authentication", expanded=True):
                hc1, hc2 = st.columns(2)
                with hc1:
                    st.markdown(f"**From**: `{h.get('From', 'N/A')}`")
                    st.markdown(f"**Subject**: `{x.get('subject', 'N/A')}`")
                    if "Reply-To" in h:
                        st.markdown(f"**Reply-To**: `{h['Reply-To']}`")
                with hc2:
                    auth = (h.get("Authentication-Results", "") + " " + h.get("Received-SPF", "")).lower()
                    spf_status = "Pass" if "spf=pass" in auth else ("Fail / Softfail" if "spf=fail" in auth or "spf=softfail" in auth else "Not reported")
                    dkim_status = "Pass" if "dkim=pass" in auth else ("Fail" if "dkim=fail" in auth else "Not reported")
                    st.markdown(f"**SPF Record**: `{spf_status}`")
                    st.markdown(f"**DKIM Signature**: `{dkim_status}`")

        # Display attachments if any
        if x.get("attachments"):
            with st.expander(f"📎 Inspected Attachments ({len(x['attachments'])})", expanded=True):
                for att in x["attachments"]:
                    st.markdown(f"• **{att['filename']}** ({att['content_type']}) — `{att['size']:,} bytes`")

        p = x.get("phishing_probability")
        st.markdown(f"**Phishing probability (ML)**: **{p:.0%}** · Overall Risk: **{res['risk_level']}**" if p is not None else
                    f"Overall Risk: **{res['risk_level']}** (ML model not available)")
        st.markdown("**Key Indicators:** " + "; ".join(e.lower() for e in res["explanations"][:6]))
        if x.get("urls"):
            st.caption("Embedded links analyzed: " + ", ".join(f"{u['domain']} → {u['score']:.0f} ({u['risk']})" for u in x["urls"]))

        from ml.phishing_model import feature_label
        show_ml(res, feature_label)
        ui.findings_table(res)
        clear_button("email")


# ---------------- Website ----------------
with tabs[2]:
    st.subheader("Website / URL Security Assessment")
    st.caption("CyberGuardian estimates URL-based security risk using structural, domain and ML-based indicators. "
               "The URL is never fetched or visited.")
    c1, c2 = st.columns([4, 1])
    c2.button("Demo URL", on_click=lambda: st.session_state.update(url_text=demo.DEMO_URL))
    url = c1.text_input("URL", key="url_text", placeholder="https://example.com/login")
    if st.button("Assess URL", type="primary") and url:
        ui.set_result("url", url_scanner.scan_url(url))
    res = ui.results().get("url")
    if res:
        ui.module_header(res, "URL")
        ch = res["extra"]["checks"]
        st.code(" | ".join(f"{k} {'✓' if v else '✗'}" for k, v in ch.items()) + f"\nRegistered domain: {res['extra']['registered_domain']}"
                f"\nRisk: {res['risk_level']}", language=None)
        show_ml(res, lambda n: FEATURE_LABELS.get(n, n))
        ui.findings_table(res)
        clear_button("url")

# ---------------- App permissions ----------------
with tabs[3]:
    st.subheader("Mobile App Permission Audit")
    mode = st.radio("Input", ["Select category + permissions", "Upload AndroidManifest.xml"], horizontal=True)
    cat = st.selectbox("App category (stated purpose)", permission_audit.CATEGORIES, key="perm_cat")
    if mode.startswith("Select"):
        opts = [g for g in permission_audit.PERMISSION_GROUPS if g != "INTERNET"]
        chosen = st.multiselect("Requested permissions", opts,
                                format_func=lambda g: f"{permission_audit.PERMISSION_GROUPS[g][1]} "
                                                      f"[{permission_audit.PERMISSION_GROUPS[g][0]}]", key="perm_sel")
        c1, c2 = st.columns(2)
        if c1.button("Audit permissions", type="primary"):
            ui.set_result("permission", permission_audit.audit_permissions(cat, set(chosen) | {"INTERNET"}, f"{cat} app"))
        if c2.button("Demo: Calculator with mic + SMS"):
            ui.set_result("permission", permission_audit.audit_permissions(**{"category": demo.DEMO_APP["category"],
                                                                              "groups": demo.DEMO_APP["permissions"]}))
    else:
        mf = st.file_uploader("AndroidManifest.xml", type=["xml"], key="manifest")
        c1, c2 = st.columns(2)
        if c1.button("Audit manifest", type="primary") and mf is not None:
            ui.set_result("permission", permission_audit.audit_manifest(mf.getvalue().decode("utf-8", "ignore"), cat))
        if c2.button("Demo manifest (Flashlight with SMS + overlay + accessibility)"):
            ui.set_result("permission", permission_audit.audit_manifest(demo.DEMO_MANIFEST, "Flashlight"))
    res = ui.results().get("permission")
    if res:
        ui.module_header(res, "Permission")
        x = res["extra"]
        st.markdown(f"**App type:** {x['category']} · **Requests:** "
                    + ", ".join(permission_audit.PERMISSION_GROUPS[g][1] for g in x["requested"]))
        st.markdown(f"**Result: {x['verdict']}**")
        if "PERM_EXCESSIVE" in {f['id'] for f in res["findings"]}:
            st.warning("The requested permissions appear excessive relative to the stated application purpose.")
        ui.findings_table(res)
        clear_button("permission")

# ---------------- Device ----------------
with tabs[4]:
    st.subheader("Device Security Audit")
    st.caption("Empirical Windows posture detection + manual self-reported security questions. 'Not sure' counts as half risk.")
    labels = {"YES": "Yes", "NO": "No", "NOT_SURE": "Not sure"}
    for k in device_audit.QUESTIONS:
        st.session_state.setdefault(f"dev_{k}", "NOT_SURE")

    c_btn1, c_btn2 = st.columns(2)
    with c_btn1:
        if st.button("🛡️ Auto-Detect Windows Security Posture",
                     help="Safely queries local Windows read-only security settings (Antivirus, Firewall, BitLocker, etc.). Zero personal files accessed; 100% local."):
            detected = device_audit.inspect_windows_security()
            if detected:
                for k, v in detected.items():
                    st.session_state[f"dev_{k}"] = v
                st.success(f"✓ Successfully detected {len(detected)} Windows security settings! Review and adjust any answers below.")
            else:
                st.info("Auto-detect is available on Windows devices. You can configure all settings manually below.")
    with c_btn2:
        st.button("Fill demo answers (MFA = No, no backup)",
                  on_click=lambda: st.session_state.update({f"dev_{k}": v for k, v in demo.DEMO_DEVICE.items()}))

    st.markdown("##### Security Questionnaire (Review or Customize Manually)")
    answers = {}
    for k, q in device_audit.QUESTIONS.items():
        answers[k] = st.radio(q[0], list(labels), format_func=labels.get, horizontal=True, key=f"dev_{k}")
    if st.button("Score device", type="primary"):
        ui.set_result("device", device_audit.audit_device(answers))
    res = ui.results().get("device")
    if res:
        ui.module_header(res, "Device")
        for f in res["findings"]:
            st.markdown(f"⚠ {f['title']}")
        clear_button("device")


st.divider()
if st.button("View Risk Dashboard →", type="primary"):
    st.switch_page("pages/2_Risk_Dashboard.py")
