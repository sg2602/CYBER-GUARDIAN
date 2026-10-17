import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from utils import ui  # noqa: E402
from utils.common import MODULE_LABELS, TIER_COLORS, TIER_LABELS  # noqa: E402

ui.setup("Risk Dashboard")
st.title("📊 Risk Dashboard")
a = ui.get_assessment()
if a is None:
    st.info("Cyber Safety Score: Not yet assessed. Run at least one module in the Security Scanner.")
    if st.button("Go to Security Scanner", type="primary"):
        st.switch_page("pages/1_Security_Scanner.py")
    st.stop()

c1, c2, c3 = st.columns([1.3, 1, 1])
with c1:
    st.plotly_chart(ui.gauge(a["score"], a["risk_level"]), width="stretch")
with c2:
    st.markdown("#### Risk level")
    st.markdown(ui.badge(a["risk_level"]) + (ui.badge("HIGH", "Partial assessment") if a["coverage"]["partial"] else ""),
                unsafe_allow_html=True)
    st.markdown(f"Score **{a['score']:.0f}** — {a['coverage']['label']}")
    if a["floor_applied"]:
        st.error("Critical-severity floor applied: a CRITICAL finding caps the score at 39.")
    if a["uncertain_modules"]:
        st.markdown(ui.uncertain_badge() + " in: " + ", ".join(MODULE_LABELS[m] for m in a["uncertain_modules"]),
                    unsafe_allow_html=True)
with c3:
    st.markdown("#### Baseline vs correlated")
    fig = go.Figure(go.Bar(x=["Plain average", "Correlated"], y=[a["baseline"], a["score"]],
                           marker_color=[TIER_COLORS[a["baseline_risk_level"]], TIER_COLORS[a["risk_level"]]],
                           text=[f"{a['baseline']:.0f} {TIER_LABELS[a['baseline_risk_level']]}",
                                 f"{a['score']:.0f} {TIER_LABELS[a['risk_level']]}"], textposition="outside"))
    fig.update_layout(height=260, yaxis_range=[0, 115], margin=dict(l=10, r=10, t=10, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#F8FAFC", family="Inter, sans-serif"))
    fig.update_xaxes(tickfont=dict(color="#F8FAFC"))
    fig.update_yaxes(tickfont=dict(color="#F8FAFC"))
    st.plotly_chart(fig, width="stretch")
    diff = a["baseline"] - a["score"]
    if a["baseline_risk_level"] != a["risk_level"]:
        st.warning(f"A plain average would report **{TIER_LABELS[a['baseline_risk_level']]}** — "
                   f"correlation reveals **{TIER_LABELS[a['risk_level']]}** ({diff:.0f} points hidden by averaging).")

st.plotly_chart(ui.module_bars(a), width="stretch")

st.subheader(f"⛓ Attack Chains & Threat Graph ({len(a['chains'])})")
if not a["chains"]:
    st.success("✓ No cross-module attack chains detected. Isolated weaknesses do not form exploitable multi-stage attack paths.")
else:
    # Interactive Graph Selector if multiple chains detected
    if len(a["chains"]) > 1:
        chain_names = [f"{c['name']} ({c['severity']}) — −{c['points']:.1f} pts" for c in a["chains"]]
        sel_idx = st.selectbox("Select attack chain to explore in the interactive threat graph:", range(len(a["chains"])),
                               format_func=lambda i: chain_names[i])
        active_chain = a["chains"][sel_idx]
    else:
        active_chain = a["chains"][0]

    # Render Interactive Plotly Directed Attack Graph
    st.plotly_chart(ui.attack_chain_graph(active_chain), width="stretch")

    # Detailed Chain Cards
    with st.expander("Detailed Attack Chain Descriptions & MITRE ATT&CK Mapping", expanded=True):
        for c in a["chains"]:
            steps = '<span class="cg-arrow">→</span>'.join(f'<span class="cg-step">{s}</span>' for s in c["steps"])
            st.markdown(f'<div class="cg-chain"><b>{c["name"]}</b> {ui.badge("CRITICAL" if c["severity"] == "CRITICAL" else "HIGH", c["severity"])}'
                        f'<span class="cg-muted">MITRE ATT&CK: {", ".join(c["attack_ids"])} · −{c["points"]:.1f} pts</span><br>'
                        f'{steps}<br><span class="cg-muted">{c["explanation"]}<br>Participating findings: '
                        f'{", ".join(c["participants"])}</span></div>', unsafe_allow_html=True)


st.subheader("Score breakdown — points lost")
st.plotly_chart(ui.waterfall(a), width="stretch")
with st.expander("Full breakdown table (reconciles exactly to the score)"):
    df = pd.DataFrame([{"Finding": b["label"], "Source": b["tag"], "Severity": b["severity"],
                        "Points lost": round(b["points"], 2)} for b in a["breakdown"]])
    st.dataframe(df, hide_index=True, width="stretch")
    st.caption(f"100 − {sum(b['points'] for b in a['breakdown']):.2f} = {a['score']:.2f}")

st.subheader("Critical & high findings")
if a["critical_findings"]:
    st.dataframe(pd.DataFrame([{"Severity": f["severity"], "Module": f["module"], "Finding": f["title"],
                                "Evidence": f["evidence"], "ATT&CK": ", ".join(f["attack_ids"])}
                               for f in a["critical_findings"]]), hide_index=True, width="stretch")
else:
    st.success("No high or critical findings.")
if st.button("Recommendations & What-If →", type="primary"):
    st.switch_page("pages/3_Recommendations_WhatIf.py")
