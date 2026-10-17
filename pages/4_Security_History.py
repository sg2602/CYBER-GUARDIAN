import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from database import database as db  # noqa: E402
from utils import ui  # noqa: E402

ui.setup("Security History")
st.title("📈 Security History")
rows = db.list_assessments()
if not rows:
    st.info("No saved assessments yet. Save one from the Report page.")
    st.stop()
df = pd.DataFrame(rows)
delta = db.improvement()
if delta is not None:
    if delta > 0:
        st.success(f"↑ Security posture improved by {delta:.0f} points since the previous assessment.")
    elif delta < 0:
        st.error(f"↓ Security posture dropped by {abs(delta):.0f} points since the previous assessment.")
    else:
        st.info("No change since the previous assessment.")
fig = go.Figure()
fig.add_scatter(x=df.created_at, y=df.overall_score, mode="lines+markers", name="Cyber Safety Score")
fig.add_scatter(x=df.created_at, y=df.baseline_score, mode="lines+markers", name="Plain average (baseline)",
                line=dict(dash="dot"))
fig.update_layout(title="Security Improvement Trend", yaxis_range=[0, 100], height=360,
                  margin=dict(l=10, r=10, t=40, b=10), legend=dict(orientation="h", y=-0.2))
st.plotly_chart(fig, width="stretch")
show = df[["assessment_id", "created_at", "overall_score", "risk_level", "coverage", "password_score", "email_score",
           "url_score", "permission_score", "device_score"]].iloc[::-1]
st.dataframe(show.rename(columns={"assessment_id": "ID", "created_at": "Date", "overall_score": "Score",
                                  "risk_level": "Risk"}), hide_index=True, width="stretch")
sel = st.selectbox("Inspect assessment", df.assessment_id.iloc[::-1])
if sel:
    c1, c2 = st.columns(2)
    c1.markdown("**Chains**")
    c1.dataframe(pd.DataFrame(db.get_chains(sel)), hide_index=True)
    c2.markdown("**Stored finding IDs** (no raw inputs are stored)")
    c2.dataframe(pd.DataFrame(db.get_findings(sel))[["finding_id", "module", "severity", "points_lost", "source"]],
                 hide_index=True)
with st.expander("Danger zone"):
    if st.button("Delete all history"):
        db.delete_all()
        st.rerun()
