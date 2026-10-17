"""CyberGuardian - Home page.   Run:  streamlit run app.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st  # noqa: E402

from utils import ui  # noqa: E402
from utils.common import MODULE_LABELS, MODULES  # noqa: E402

PAGES = [
    ("pages/1_Security_Scanner.py", "Security Scanner", "🔍"),
    ("pages/2_Risk_Dashboard.py", "Risk Dashboard", "📊"),
    ("pages/3_Recommendations_WhatIf.py", "Recommendations & What-If", "🛠"),
    ("pages/4_Security_History.py", "Security History", "📈"),
    ("pages/5_Report.py", "Report", "📄"),
    ("pages/6_About_Model_Performance.py", "About / Model Performance", "ℹ️"),
]


def home():
    ui.setup("Home")

    st.title("🛡️ CyberGuardian")
    st.markdown("#### Intelligent Personal Cybersecurity Risk Assessment System")
    st.caption(ui.SUBTITLE)

    a = ui.get_assessment()
    c1, c2 = st.columns([1, 2])
    with c1:
        if a is None:
            st.markdown('<div class="cg-card"><div class="cg-muted">Cyber Safety Score</div>'
                        '<div class="cg-big">—</div><div>Not yet assessed</div></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="cg-card"><div class="cg-muted">Cyber Safety Score</div>'
                        f'<div class="cg-big">{a["score"]:.0f}<span style="font-size:1.2rem">/100</span></div>'
                        f'{ui.badge(a["risk_level"])}<div class="cg-muted">{a["coverage"]["label"]}</div></div>',
                        unsafe_allow_html=True)
        if st.button("▶ Start Security Assessment", type="primary", width="stretch"):
            st.switch_page("pages/1_Security_Scanner.py")
        if st.button("Load demo profile (all 5 modules)", width="stretch",
                     help="Fills every module with the fictitious presentation storyline"):
            from modules.device_audit import audit_device
            from modules.email_analyzer import analyze_email
            from modules.password_audit import audit_password
            from modules.permission_audit import audit_permissions
            from modules.url_scanner import scan_url
            from utils import demo_inputs as d
            ui.set_result("password", audit_password(d.DEMO_PASSWORD))
            ui.set_result("email", analyze_email(d.DEMO_EMAIL))
            ui.set_result("url", scan_url(d.DEMO_URL))
            ui.set_result("permission", audit_permissions(d.DEMO_APP["category"], d.DEMO_APP["permissions"], "Calculator (demo)"))
            ui.set_result("device", audit_device(d.DEMO_DEVICE))
            st.switch_page("pages/2_Risk_Dashboard.py")
        if a is not None and st.button("Clear current assessment", width="stretch"):
            st.session_state["results"] = {}
            st.session_state.pop("assessment", None)
            st.rerun()
    with c2:
        st.markdown("""
**How it works**

1. **Scan** five areas: password, email, website/URL, app permissions and device.
2. The **Threat Correlation Engine** looks for weaknesses that *combine* into attack chains
   (mapped to MITRE ATT&CK) instead of averaging them away.
3. The **Risk Engine** produces a 0–100 *Cyber Safety Score* (higher = safer) where every lost point is traceable.
4. **Recommendations + What-If simulator** show which fixes raise your score the most for the least effort.
5. Save the assessment and track your **security history** over time.
""")
        res = ui.results()
        cols = st.columns(5)
        for col, m in zip(cols, MODULES):
            r = res.get(m)
            col.markdown(f"**{MODULE_LABELS[m].split()[0]}**<br>" +
                         (f"{r['score']:.0f}/100<br>{ui.badge(r['risk_level'])}" if r and r.get("assessed") else ui.badge(None)),
                         unsafe_allow_html=True)

    st.info("🔒 Privacy: password inputs are processed locally and are never stored. Emails, URLs and manifests are analysed "
            "in memory; only scores and finding IDs are saved. URLs are never visited.")
    st.caption("CyberGuardian estimates personal security risk using rules, self-reported answers and ML models; it is not an "
               "antivirus or vulnerability scanner.")


nav = st.navigation([st.Page(home, title="Home", icon="🛡️", default=True)] +
                   [st.Page(path, title=title, icon=icon) for path, title, icon in PAGES])
nav.run()
