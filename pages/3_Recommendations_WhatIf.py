import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from risk.recommendation_engine import group_by_priority  # noqa: E402
from risk.whatif_simulator import optimize_budget, simulate  # noqa: E402
from utils import ui  # noqa: E402
from utils.common import TIER_LABELS  # noqa: E402

ui.setup("Recommendations & What-If")
st.title("🛠 Recommendations & What-If Simulator")
a = ui.get_assessment()
if a is None:
    st.info("Not yet assessed. Run the Security Scanner first.")
    st.stop()

st.subheader("What-If remediation simulator")
st.markdown(f"Current Cyber Safety Score: **{a['score']:.0f} ({TIER_LABELS[a['risk_level']]})**")
rows = a["whatif"]
if rows:
    df = pd.DataFrame([{"Action": r["title"], "Effort": r["effort"], "New score": round(r["new_score"]),
                        "Gain": f"{r['gain']:+.0f}", "Breaks chain": ", ".join(r["breaks_chains"])} for r in rows])
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        column_config={
            "Action": st.column_config.TextColumn("Remediation Action", width="large"),
            "Effort": st.column_config.TextColumn("Effort", width="small"),
            "New score": st.column_config.NumberColumn("New Score", width="small"),
            "Gain": st.column_config.TextColumn("Gain", width="small"),
            "Breaks chain": st.column_config.TextColumn("Breaks Attack Chain", width="medium"),
        }
    )
    st.caption("Ranked by score gain ÷ effort (Low = 1, Medium = 2, High = 3). Each row re-runs the correlation + risk engine "
               "with that action's findings removed (counterfactual).")

    st.markdown("---")
    st.markdown("### ⏱️ Security Time Budget Optimizer")
    st.caption("Don't have time to fix everything at once? Pick your time budget — CyberGuardian solves the non-linear "
               "counterfactual knapsack problem to find the optimal combination of fixes that maximizes your score and "
               "breaks the highest number of attack chains.")

    budget_options = {
        "⚡ Quick Wins (15 mins · Low Effort)": 1,
        "🛡️ Standard Hardening (30 mins · 2 Effort pts)": 2,
        "🚀 Substantial Upgrade (45 mins · 3 Effort pts)": 3,
        "🏆 Maximum Overhaul (60+ mins · 5 Effort pts)": 5,
    }

    selected_label = st.radio(
        "Select your available remediation time budget:",
        options=list(budget_options.keys()),
        index=1,
        horizontal=True,
        key="budget_optimizer_radio",
    )
    selected_budget = budget_options[selected_label]
    opt = optimize_budget(a["modules"], max_effort=selected_budget, current=a)

    if opt and opt["actions"]:
        b_col1, b_col2, b_col3 = st.columns(3)
        with b_col1:
            st.metric("Projected Safety Score", f"{opt['projected_score']:.0f} / 100", f"{opt['gain']:+.0f} pts")
            st.caption(f"Risk Tier: **{TIER_LABELS.get(opt['projected_risk_level'], opt['projected_risk_level'])}**")
        with b_col2:
            st.metric("Effort Allocated", f"{opt['total_effort']} / {selected_budget} pts")
            st.caption(f"{len(opt['actions'])} action(s) selected")
        with b_col3:
            st.metric("Chains Dismantled", f"{len(opt['broken_chains'])}")
            if opt["broken_chains"]:
                st.caption("⛓ " + ", ".join(opt["broken_chains"]))
            else:
                st.caption("No multi-stage chains active")

        st.markdown("**Recommended optimal action set:**")
        for act in opt["action_details"]:
            st.markdown(f"- **{act['title']}** (`{act['effort']}` effort)")

        btn_c1, btn_c2 = st.columns([1, 1])
        with btn_c1:
            if st.button("🎯 Apply These Actions in Interactive Simulator", key="btn_apply_budget", type="primary", use_container_width=True):
                for r in rows:
                    st.session_state[f"wi_{r['action_id']}"] = (r["action_id"] in opt["actions"])
                st.rerun()
        with btn_c2:
            if st.button("🔄 Clear Simulator Checkboxes", key="btn_clear_budget", use_container_width=True):
                for r in rows:
                    st.session_state[f"wi_{r['action_id']}"] = False
                st.rerun()
    else:
        st.info("No actionable findings fit within this budget or security is already optimal.")

    st.markdown("---")

left, right = st.columns([1.1, 1])
with left:
    st.subheader("Prioritised recommendations")
    icons = {"Immediate": "🔴", "Soon": "🟠", "Good practice": "🟢"}
    for prio, recs in group_by_priority(a["recommendations"]).items():
        if not recs:
            continue
        st.markdown(f"#### {icons[prio]} {prio}")
        for r in recs:
            with st.expander(f"{r['title']}  ·  effort {r['effort']}" + ("  ·  ⛓ breaks chain" if r["breaks_chains"] else "")):
                for s in r["steps"]:
                    st.markdown(f"- {s}")
                st.caption("Triggered by: " + ", ".join(r["triggered_by"] or ["-"]) +
                           (" · Breaks: " + ", ".join(r["breaks_chains"]) if r["breaks_chains"] else ""))

with right:
    st.subheader("Tick actions → projected score")
    if not rows:
        st.success("Nothing to fix - no actionable findings.")
    else:
        chosen = [r["action_id"] for r in rows if st.checkbox(f"{r['title']} ({r['effort']})", key=f"wi_{r['action_id']}")]
        s = simulate(a["modules"], chosen) if chosen else a
        st.plotly_chart(ui.gauge(s["score"], s["risk_level"], "Projected score" if chosen else "Current score"),
                        width="stretch")
        if chosen:
            st.markdown(f"Projected: **{s['score']:.0f}** ({TIER_LABELS[s['risk_level']]}), "
                        f"{s['score'] - a['score']:+.0f} points · chains remaining: "
                        f"{', '.join(c['id'] for c in s['chains']) or 'none'}")
