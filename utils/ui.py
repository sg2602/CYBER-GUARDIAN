"""Shared Streamlit helpers: page setup, session state, badges and charts."""
from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from utils.common import MODULE_LABELS, MODULES, TIER_COLORS, TIER_LABELS

APP_TITLE = "CyberGuardian"
SUBTITLE = "An AI-Assisted Personal Cybersecurity Risk Assessment and Security Recommendation Platform"

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&display=swap');

/* Global Typography */
html, body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    letter-spacing: normal;
}

h1, h2, h3, h4, .cg-headline {
    font-family: 'Outfit', sans-serif !important;
    letter-spacing: -0.025em;
    font-weight: 700;
}

.block-container {
    padding-top: 1.8rem;
    padding-bottom: 3rem;
    max-width: 1240px;
}

/* Glassmorphic Cyber Card Containers */
.cg-card {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid rgba(140, 150, 170, 0.22);
    border-radius: 12px;
    padding: 18px 22px;
    margin-bottom: 14px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}

.cg-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(0, 0, 0, 0.12);
    border-color: rgba(66, 153, 225, 0.45);
}

/* Multi-Stage Attack Chain Threat Box with Pulsing Red Accent */
.cg-chain {
    border-left: 5px solid #e53e3e;
    background: linear-gradient(90deg, rgba(229, 62, 62, 0.12) 0%, rgba(229, 62, 62, 0.02) 100%);
    padding: 14px 18px;
    border-radius: 8px;
    margin: 10px 0;
    border-top: 1px solid rgba(229, 62, 62, 0.22);
    border-bottom: 1px solid rgba(229, 62, 62, 0.22);
    border-right: 1px solid rgba(229, 62, 62, 0.12);
    box-shadow: 0 4px 16px rgba(229, 62, 62, 0.08);
    transition: all 0.2s ease;
}

.cg-chain:hover {
    border-left-color: #ff3838;
    box-shadow: 0 6px 22px rgba(229, 62, 62, 0.18);
}

.cg-step {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    background: rgba(128, 128, 128, 0.15);
    border: 1px solid rgba(128, 128, 128, 0.25);
    margin: 3px 0;
    font-size: 0.88rem;
    font-weight: 500;
}

.cg-arrow {
    margin: 0 8px;
    color: #e53e3e;
    font-weight: 800;
}

.cg-muted {
    opacity: 0.72;
    font-size: 0.88rem;
}

/* Metric Display Numbers */
.cg-big {
    font-family: 'Outfit', sans-serif;
    font-size: 3.4rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.03em;
}

/* Status Badges with Subtle Glow */
.cg-badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 12px;
    border-radius: 999px;
    color: #fff !important;
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.16);
    margin-right: 6px;
    white-space: nowrap;
}

.cg-badge-critical {
    box-shadow: 0 0 10px rgba(229, 62, 62, 0.5);
    animation: cg-pulse-red 2s infinite;
}

.cg-badge-uncertain {
    background: linear-gradient(135deg, #7c3aed, #6d28d9) !important;
    box-shadow: 0 0 10px rgba(124, 58, 237, 0.4);
}

@keyframes cg-pulse-red {
    0% { box-shadow: 0 0 0 0 rgba(229, 62, 62, 0.6); }
    70% { box-shadow: 0 0 0 6px rgba(229, 62, 62, 0); }
    100% { box-shadow: 0 0 0 0 rgba(229, 62, 62, 0); }
}

/* MITRE ATT&CK & Tech Tags */
.cg-mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85em;
}

.cg-mitre-tag {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(99, 102, 241, 0.15);
    color: #4f46e5;
    border: 1px solid rgba(99, 102, 241, 0.35);
    margin: 2px 4px 2px 0;
    font-weight: 600;
}

/* Polished Streamlit Button Micro-Interactions */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    letter-spacing: 0.01em;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}

.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.12);
}

div[data-testid="stMetricValue"] {
    font-family: 'Outfit', sans-serif !important;
    font-weight: 700 !important;
}

/* Sidebar width & text spacing - prevents truncation */
section[data-testid="stSidebar"],
section[data-testid="stSidebar"] > div:first-child,
div[data-testid="stSidebarNav"] {
    min-width: 290px !important;
}

section[data-testid="stSidebar"] span {
    font-size: 0.95rem !important;
    white-space: nowrap !important;
}

/* Ensure code blocks and tables wrap properly without clipping */
pre, code {
    white-space: pre-wrap !important;
    word-break: break-word !important;
}

.stDataFrame {
    width: 100% !important;
}

/* Finding Cards - replaces cramped dataframe cells with zero text clipping */
.cg-finding-card {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(140, 150, 170, 0.18);
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 10px;
    transition: all 0.2s ease;
}

.cg-finding-card:hover {
    border-color: rgba(0, 210, 255, 0.4);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
}

.cg-finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 6px;
}

.cg-finding-title {
    font-size: 1rem;
    font-weight: 600;
    color: #F8FAFC;
}

.cg-finding-evidence {
    font-size: 0.88rem;
    color: #94A3B8;
    line-height: 1.5;
    word-break: break-word;
}

.cg-points-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    font-weight: 700;
    color: #EF4444;
    background: rgba(239, 68, 68, 0.12);
    padding: 2px 8px;
    border-radius: 6px;
    border: 1px solid rgba(239, 68, 68, 0.25);
}
</style>
"""


def setup(title: str):
    st.set_page_config(page_title=f"{title} · {APP_TITLE}", page_icon="🛡️", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    init_state()


def init_state():
    if "results" not in st.session_state:
        st.session_state["results"] = {}
    if "inputs_meta" not in st.session_state:
        st.session_state["inputs_meta"] = {}


def results() -> dict:
    init_state()
    return st.session_state["results"]


def set_result(module: str, res: dict):
    init_state()
    st.session_state["results"][module] = res
    st.session_state.pop("assessment", None)


def clear_result(module: str):
    st.session_state["results"].pop(module, None)
    st.session_state.pop("assessment", None)


def get_assessment():
    """Run (or reuse) the full assessment for the current module results."""
    from risk.assessment import run_assessment
    res = results()
    if not any(r.get("assessed") for r in res.values()):
        return None
    if "assessment" not in st.session_state:
        st.session_state["assessment"] = run_assessment(res)
    return st.session_state["assessment"]


def badge(tier: str | None, text: str | None = None) -> str:
    if not tier:
        return '<span class="cg-badge" style="background:#7b8794">NOT ASSESSED</span>'
    extra_class = " cg-badge-critical" if tier == "CRITICAL" else ""
    return f'<span class="cg-badge{extra_class}" style="background:{TIER_COLORS[tier]}">{text or TIER_LABELS[tier]}</span>'


def uncertain_badge() -> str:
    return '<span class="cg-badge cg-badge-uncertain">UNCERTAIN — verify manually</span>'


def gauge(score: float, tier: str, title: str = "Cyber Safety Score") -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=round(score, 1),
        number={"suffix": "/100", "font": {"size": 38, "family": "Outfit, sans-serif", "color": "#F8FAFC"}},
        title={"text": title, "font": {"family": "Outfit, sans-serif", "size": 18, "color": "#F8FAFC"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "rgba(255,255,255,0.3)"},
            "bar": {"color": TIER_COLORS[tier], "thickness": 0.28},
            "steps": [
                {"range": [0, 40], "color": "rgba(239,68,68,0.25)"},
                {"range": [40, 60], "color": "rgba(249,115,22,0.25)"},
                {"range": [60, 80], "color": "rgba(245,158,11,0.25)"},
                {"range": [80, 100], "color": "rgba(16,185,129,0.25)"}
            ]
        }
    ))
    fig.update_layout(height=280, margin=dict(l=40, r=40, t=60, b=10),
                      font=dict(family="Inter, sans-serif", color="#F8FAFC"),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def shap_bar(shap_top: list, label_fn) -> go.Figure:
    items = list(reversed(shap_top))
    fig = go.Figure(go.Bar(x=[v for _, v in items], y=[label_fn(n) for n, _ in items], orientation="h",
                           marker_color=["#EF4444" if v > 0 else "#10B981" for _, v in items]))
    fig.update_layout(height=60 + 34 * len(items), margin=dict(l=10, r=10, t=30, b=10),
                      title=dict(text="SHAP: contribution to phishing estimate (red = towards phishing)",
                                 font=dict(color="#F8FAFC", family="Outfit, sans-serif")),
                      xaxis_title="SHAP value",
                      font=dict(color="#F8FAFC", family="Inter, sans-serif"),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def waterfall(a: dict, top: int = 10) -> go.Figure:
    items = a["breakdown"][:top]
    rest = a["breakdown"][top:]
    xs, ys, measures = ["Start"], [100], ["absolute"]
    for b in items:
        xs.append(b["label"][:60] + ("…" if len(b["label"]) > 60 else "") + f" [{b['tag']}]")
        ys.append(-b["points"])
        measures.append("relative")
    if rest:
        xs.append(f"{len(rest)} smaller findings")
        ys.append(-sum(b["points"] for b in rest))
        measures.append("relative")
    xs.append("Cyber Safety Score")
    ys.append(a["score"])
    measures.append("total")
    fig = go.Figure(go.Waterfall(orientation="h", measure=measures, y=xs, x=ys,
                                 text=[f"{y:+.1f}" if m == "relative" else f"{y:.1f}" for y, m in zip(ys, measures)],
                                 textposition="outside",
                                 decreasing={"marker": {"color": "#EF4444"}}, totals={"marker": {"color": "#00D2FF"}},
                                 increasing={"marker": {"color": "#10B981"}},
                                 connector={"line": {"color": "rgba(255,255,255,0.25)"}}))
    fig.update_layout(height=90 + 34 * len(xs), margin=dict(l=10, r=40, t=40, b=10), showlegend=False,
                      title=dict(text="Where every point went (100 − points lost = score)",
                                 font=dict(color="#F8FAFC", family="Outfit, sans-serif")),
                      xaxis_range=[0, 112],
                      font=dict(color="#F8FAFC", family="Inter, sans-serif"),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    fig.update_yaxes(autorange="reversed", tickfont={"size": 11, "color": "#F8FAFC"})
    fig.update_xaxes(tickfont={"color": "#F8FAFC"})
    return fig


def module_bars(a: dict) -> go.Figure:
    mods = [m for m in MODULES if a["modules"][m].get("assessed")]
    raw = [a["modules"][m]["score"] for m in mods]
    eff = [a["effective_module_scores"].get(m, a["modules"][m]["score"]) for m in mods]
    fig = go.Figure()
    fig.add_bar(x=[MODULE_LABELS[m] for m in mods], y=raw, name="Module score",
                marker_color=[TIER_COLORS[a["modules"][m]["risk_level"]] for m in mods],
                text=[f"{v:.0f}" for v in raw], textposition="outside",
                textfont=dict(color="#F8FAFC"))
    if any(e < r - 1e-9 for e, r in zip(eff, raw)):
        fig.add_scatter(x=[MODULE_LABELS[m] for m in mods], y=eff, mode="markers", name="After chain escalation",
                        marker=dict(symbol="line-ew-open", size=40, color="#00D2FF", line=dict(width=3)))
    fig.update_layout(height=330, yaxis_range=[0, 110], margin=dict(l=10, r=10, t=30, b=10),
                      title=dict(text="Module scores (higher = safer)",
                                 font=dict(color="#F8FAFC", family="Outfit, sans-serif")),
                      legend=dict(orientation="h", y=-0.2, font=dict(color="#F8FAFC")),
                      font=dict(color="#F8FAFC", family="Inter, sans-serif"),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    fig.update_xaxes(tickfont={"color": "#F8FAFC"})
    fig.update_yaxes(tickfont={"color": "#F8FAFC"})
    return fig


def findings_table(res: dict):
    if not res or not res.get("findings"):
        st.success("✓ No vulnerabilities detected in this module.")
        return

    st.markdown("##### Detailed Vulnerability Findings")
    for f in res["findings"]:
        sev = f["severity"]
        sev_class = "cg-badge-critical" if sev == "CRITICAL" else ""
        color = TIER_COLORS.get(sev, "#64748B")
        pts = f.get("points_lost", 0)
        pts_str = f"−{pts:.1f} pts" if pts else "0 pts"
        fid = f.get("id", "")
        evidence = f.get("evidence", "")
        title = f.get("title", "")

        html = f"""<div class="cg-finding-card">
            <div class="cg-finding-header">
                <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px;">
                    <span class="cg-badge {sev_class}" style="background:{color}">{sev}</span>
                    <span class="cg-finding-title">{title}</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span class="cg-points-tag">{pts_str}</span>
                    <span class="cg-mitre-tag">{fid}</span>
                </div>
            </div>
            <div class="cg-finding-evidence">{evidence}</div>
        </div>"""
        st.markdown(html, unsafe_allow_html=True)


def module_header(res: dict, label: str):
    c1, c2 = st.columns([1, 3])
    c1.metric(f"{label} score", f"{res['score']:.0f}/100")
    html = badge(res["risk_level"])
    if res.get("uncertain"):
        html += uncertain_badge()
    c2.markdown("<br>" + html, unsafe_allow_html=True)


def attack_chain_graph(chain: dict) -> go.Figure:
    """Generate an interactive Plotly directed graph of a MITRE ATT&CK attack chain.

    Visualizes:
    - Root Vulnerabilities (bottom tier, red/gray circles)
    - Adversary Attack Steps (middle tier, red diamonds with directed arrows)
    - Remediation Interceptors (top tier, green shields that break the chain)
    """
    from risk.recommendation_engine import ACTIONS

    steps = chain.get("steps", [])
    participants = chain.get("participants", [])
    breakers = chain.get("breaks_with", [])
    attack_ids = chain.get("attack_ids", [])
    n_steps = max(len(steps), 1)

    fig = go.Figure()

    # Steps along X axis
    step_xs = [i * (10.0 / max(n_steps - 1, 1)) if n_steps > 1 else 5.0 for i in range(n_steps)]
    step_y = 1.0

    # 1. Directed arrows between attack steps
    for i in range(n_steps - 1):
        x0, x1 = step_xs[i], step_xs[i + 1]
        fig.add_annotation(
            x=x1 - 0.35, y=step_y, ax=x0 + 0.35, ay=step_y,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=2, arrowsize=1.4, arrowwidth=2.5,
            arrowcolor="#EF4444" if chain.get("severity") == "CRITICAL" else "#F97316"
        )

    # 2. Attack Step Nodes
    step_hovers = []
    for i, s in enumerate(steps):
        aid = attack_ids[i] if i < len(attack_ids) else ""
        step_hovers.append(f"<b>Stage {i+1}</b>: {s}<br><b>MITRE ATT&CK</b>: {aid or 'Multi-stage exploit'}")

    fig.add_trace(go.Scatter(
        x=step_xs, y=[step_y] * n_steps,
        mode="markers+text",
        marker=dict(size=44, color="#EF4444" if chain.get("severity") == "CRITICAL" else "#F97316",
                    symbol="diamond", line=dict(width=2.5, color="#ffffff")),
        text=[f"S{i+1}" for i in range(n_steps)],
        textposition="middle center",
        textfont=dict(color="#ffffff", size=13, family="Outfit, sans-serif"),
        hovertext=step_hovers,
        hoverinfo="text",
        name="Adversary Attack Step",
        showlegend=True
    ))

    # Text descriptions below step markers
    for x, s, aid in zip(step_xs, steps, attack_ids + [""] * (n_steps - len(attack_ids))):
        short_s = s.split("(")[0].strip()
        if len(short_s) > 28:
            short_s = short_s[:25] + "…"
        fig.add_annotation(
            x=x, y=step_y - 0.22,
            text=f"<b>{aid}</b><br>{short_s}" if aid else short_s,
            showarrow=False, font=dict(size=10.5, color="#E2E8F0"),
            align="center"
        )

    # 3. Root Vulnerabilities (bottom tier)
    if participants:
        n_p = len(participants)
        part_xs = [i * (10.0 / max(n_p - 1, 1)) if n_p > 1 else 5.0 for i in range(n_p)]
        part_y = 0.25

        for px in part_xs:
            closest_sx = min(step_xs, key=lambda sx: abs(sx - px))
            fig.add_shape(type="line", x0=px, y0=part_y + 0.1, x1=closest_sx, y1=step_y - 0.12,
                          line=dict(color="rgba(239,68,68,0.35)", width=1.5, dash="dot"))

        fig.add_trace(go.Scatter(
            x=part_xs, y=[part_y] * n_p,
            mode="markers+text",
            marker=dict(size=24, color="#334155", line=dict(width=2, color="#EF4444")),
            text=participants,
            textposition="bottom center",
            textfont=dict(size=10, color="#FCA5A5", family="JetBrains Mono, monospace"),
            hovertext=[f"<b>Exploited Vulnerability</b>: {p}" for p in participants],
            hoverinfo="text",
            name="User Vulnerability",
            showlegend=True
        ))

    # 4. Remediation Interceptors (top tier)
    if breakers:
        n_b = min(len(breakers), 4)
        active_breakers = breakers[:n_b]
        break_xs = [i * (10.0 / max(n_b - 1, 1)) if n_b > 1 else 5.0 for i in range(n_b)]
        break_y = 1.75

        for bx in break_xs:
            closest_sx = min(step_xs, key=lambda sx: abs(sx - bx))
            fig.add_shape(type="line", x0=bx, y0=break_y - 0.1, x1=closest_sx, y1=step_y + 0.12,
                          line=dict(color="rgba(16,185,129,0.5)", width=1.5, dash="dash"))

        breaker_titles = [ACTIONS.get(b, {}).get("title", b) for b in active_breakers]
        short_titles = [t[:24] + "…" if len(t) > 24 else t for t in breaker_titles]

        fig.add_trace(go.Scatter(
            x=break_xs, y=[break_y] * n_b,
            mode="markers+text",
            marker=dict(size=26, color="#10B981", symbol="square", line=dict(width=1.5, color="#ffffff")),
            text=short_titles,
            textposition="top center",
            textfont=dict(size=10, color="#6EE7B7", family="Inter, sans-serif"),
            hovertext=[f"<b>Remediation</b>: {t}<br><i>Breaks this attack chain</i>" for t in breaker_titles],
            hoverinfo="text",
            name="Remediation Barrier (Breaks Chain)",
            showlegend=True
        ))

    fig.update_layout(
        title=dict(text=f"<b>Attack Path: {chain.get('name', 'Attack Chain')}</b> ({chain.get('severity', 'HIGH')}) — MITRE ATT&CK: {', '.join(chain.get('attack_ids', []))}",
                   font=dict(color="#F8FAFC", family="Outfit, sans-serif")),
        xaxis=dict(visible=False, range=[-1.0, 11.0]),
        yaxis=dict(visible=False, range=[0.0, 2.05]),
        height=320,
        margin=dict(l=15, r=15, t=45, b=25),
        legend=dict(orientation="h", y=-0.08, x=0.05, font=dict(size=10, color="#F8FAFC")),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#F8FAFC")
    )
    return fig

