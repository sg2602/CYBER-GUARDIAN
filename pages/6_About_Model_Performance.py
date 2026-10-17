import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from risk.chain_rules import CHAIN_RULES  # noqa: E402
from utils import ui  # noqa: E402
from utils.common import RESULTS_DIR  # noqa: E402

ui.setup("About / Model Performance")
st.title("ℹ️ About & Model Performance")

st.subheader("Novelty")
st.markdown("""
> CyberGuardian is a personal cybersecurity assessment platform whose risk engine models how weaknesses combine into
> attack chains, rather than scoring them independently. Its contributions are: (1) a cross-module Threat Correlation
> Engine with compound-risk escalation and critical-severity floors, mapped to MITRE ATT&CK; (2) a counterfactual
> What-If Remediation Simulator that ranks actions by risk reduction per unit of effort; (3) unified score traceability
> across rule-based and ML (SHAP) evidence; and (4) rule–ML disagreement surfaced as explicit uncertainty, plus
> assessment-coverage confidence. An India-localized phishing/scam rule set is included as an additional contribution.
""")
st.dataframe(pd.DataFrame([{"Chain": c["id"], "Name": c["name"], "ATT&CK": ", ".join(c["attack_ids"]),
                            "Severity": c["severity"], "Effect": c["effect"]["type"]} for c in CHAIN_RULES]),
             hide_index=True, width="stretch")

st.subheader("ML model performance (held-out test sets, real runs)")
mpath = RESULTS_DIR / "ml_metrics.csv"
if mpath.exists():
    m = pd.read_csv(mpath)
    st.dataframe(m[["task", "model", "selected", "accuracy", "precision", "recall", "f1", "tp", "fp", "fn", "tn",
                    "n_train", "n_test", "dataset"]], hide_index=True, width="stretch")
    st.caption("Precision = how many flagged items were truly phishing; recall = how many phishing items were caught. "
               "Both matter more than accuracy because false negatives and false positives have different costs.")
    imgs = sorted(RESULTS_DIR.glob("confusion_*.png"))
    cols = st.columns(4)
    for i, p in enumerate(imgs):
        cols[i % 4].image(str(p), caption=p.stem)
else:
    st.warning("No metrics yet - run `python ml/train_url_model.py` and `python ml/train_phishing_model.py`.")

st.subheader("Novelty evidence (evaluation outputs)")
for name, title in [("scenario_study.csv", "Scenario study: plain average vs correlation engine"),
                    ("adversarial_url_results.csv", "Adversarial URL robustness (detection rate)"),
                    ("disagreement_stats.csv", "Rule–ML disagreement statistics"),
                    ("india_testset_results.csv", "India-localized test set")]:
    p = RESULTS_DIR / name
    if p.exists():
        st.markdown(f"**{title}**")
        st.dataframe(pd.read_csv(p), hide_index=True, width="stretch")
for img in ["scenario_study.png", "adversarial_url.png"]:
    if (RESULTS_DIR / img).exists():
        st.image(str(RESULTS_DIR / img))

st.subheader("Limitations")
st.markdown("""
- URL analysis is **lexical only** - pages are never fetched, so content-based phishing on clean-looking URLs can be missed.
- The device audit is **self-reported**; wrong answers give a wrong score.
- ML models reflect **dataset bias** (public corpora, mostly English/Western, different years); India-specific scams rely on rules.
- Rules, brand lists and the India scam lexicon **need maintenance** as attacker tactics change.
- Scores are guidance, not guarantees. CyberGuardian is not an antivirus, vulnerability scanner or IDS.
""")
