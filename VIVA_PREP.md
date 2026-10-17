# CyberGuardian — Viva Preparation

Short, defensible answers. Numbers come from `results/` (real runs) — quote them, don't round them up.

---

### 1. What is your novelty?
Not phishing detection itself — that is well studied. Our novelty is **how the risk is reasoned about**:
1. **Threat Correlation Engine (C1):** data-driven rules detect when findings from *different* modules combine into
   an attack chain (e.g. weak password + no MFA + credential phish = account takeover), add a compound-risk penalty,
   apply a critical floor, and map each chain to MITRE ATT&CK.
2. **What-If simulator (C2):** removes the findings an action fixes, re-runs the whole engine, and ranks actions by
   score gain ÷ effort — a counterfactual explanation of "what should I do first".
3. **Score traceability (C3):** every point lost from 100 is traced to a rule finding, an ML finding (with SHAP
   features), or a correlation finding; `100 − Σ points = score` is unit-tested.
4. **Uncertainty (C4):** rule-vs-ML disagreement is shown as "UNCERTAIN — verify manually", and the score states its
   coverage ("based on 3 of 5 modules").
5. **India-localized scam rules (C5).**

### 2. Why not just a weighted average?
Because averaging hides compound risk. Scenario P02: good password, good device, clean app, but a live
credential-harvest email → plain average **65 (MODERATE)**. The user is one click from losing their account.
CyberGuardian → **39 (CRITICAL)**. Across 13 profiles, the plain average labelled **7 of 9** dangerous profiles as
LOW/MODERATE; the correlation engine **2 of 9**. Exact tier agreement 5/13 vs 11/13.
Be ready to add: the study is small and author-labelled, and the HIGH-chain cap was added after the first run (the
ablation without it is reported: 8/13, 5/9 missed).

### 3. Why rules + ML instead of only ML?
* Rules encode domain knowledge that public datasets don't contain — the **India rules** raised rule-layer recall on
  our India test set from 38 % to 52 % with **0 %** false positives, while the ML model (trained on Western emails)
  flagged 57 % of legitimate Indian messages.
* Rules are explainable and robust to some shifts: on the "long benign path" perturbation, ML-only detection fell to
  47 %, the hybrid kept 58 % (91 % flagged at least MODERATE).
* ML catches what rules miss: on ordinary phishing URLs rules alone detect only ~3 % at the HIGH threshold (most
  phishing URLs are compromised sites, not brand look-alikes) while ML detects 93 %.
* Honest point: on the standard email test set ML alone is already ~99 % F1; the fusion weights were chosen on
  out-of-fold training data (`ml/select_fusion.py`), and for email that gave 70 % ML / 30 % rules.

### 4. Why SHAP only on the ML modules?
SHAP explains a *model's* prediction by attributing it to input features. Rule modules have no model — their
explanation *is* the rule that fired ("Reply-To differs from sender domain"). Forcing SHAP onto rules would be
explaining a function we wrote by hand with an approximation of itself. We use TreeExplainer for RF/XGBoost (exact
for trees) and exact linear SHAP for logistic regression.

### 5. How do you protect user privacy?
* Passwords: processed in memory, form cleared on submit, never stored (not hashed either), never logged, and finding
  evidence never quotes any part of the password.
* Emails/URLs/manifests: analysed in memory; URLs are never fetched.
* SQLite stores only scores, finding IDs, chain IDs, severities, ATT&CK IDs.
* A unit test saves an assessment containing a secret password, URL and email-body marker and asserts none of those
  bytes appear in the DB file or the report.

### 6. How did you evaluate?
1. ML: stratified 80/20 split, accuracy/precision/recall/F1 + confusion matrices on held-out data
   (URL RF F1 0.90 on 16,942 URLs; email LR F1 0.99 on 1,827 emails).
2. Scenario study for C1 (13 profiles, plain average vs correlation).
3. Adversarial URL test (5 perturbations × 300 held-out phishing URLs; rules-only vs ML-only vs hybrid).
4. Rule–ML disagreement statistics on the test splits.
5. India-localized test set (21 scams + 7 legit) with and without the India rules.
6. 73 pytest tests + 113 module test cases (105 pass; failures documented, not hidden).

### 7. Why precision/recall over accuracy?
Classes are imbalanced and errors have different costs. A model that says "legitimate" for everything can still have
high accuracy. **Recall** = how much phishing we catch (a miss leaves the user exposed); **precision** = how often a
warning is real (too many false alarms and users ignore the tool). F1 balances them.

### 8. What are the limitations?
* Lexical URL analysis only — no page content; the URL model makes false positives on unfamiliar legitimate deep links
  (stackoverflow/bbc in our test suite), which the UNCERTAIN badge flags.
* Device audit is self-reported.
* Dataset bias: English/Western corpora; corpus-style differences inflate email accuracy; the URL dataset had a
  PhiUSIIL artefact we had to fix (accuracy went from 0.99 to an honest 0.90).
* The UNCERTAIN flag fires too often (38–48 %) because rule scores are not calibrated; it does concentrate errors
  (URL error rate 15 % when flagged vs 7 % when not).
* Chains only cover patterns we wrote (e.g. no chain for password reuse + no MFA without an observed lure).

### 9. What is MITRE ATT&CK and why map to it?
A public knowledge base of real adversary tactics and techniques with stable IDs (e.g. T1566 Phishing, T1110 Brute
Force, T1078 Valid Accounts, T1417 Input Capture on mobile). Mapping findings and chains to it (a) grounds our
chains in observed attacker behaviour rather than our imagination, (b) gives a shared vocabulary with SOC/industry
tools, and (c) makes the chain steps explainable ("T1566 → T1110 → T1078").

### 10. How does the What-If simulator work?
Each action lists the finding IDs it resolves (wildcards allowed, e.g. `PWD_*`). For each action we deep-copy the
module results, delete those findings, recompute module scores, **re-run the correlation engine and the risk engine**
(so broken chains disappear and floors lift), and record the new score. Ranking = gain ÷ effort weight
(Low 1, Medium 2, High 3). "Top 3" applies the three best actions *together* (joint effect, not a sum of gains).
The dashboard lets the user tick any combination and see the projected score live.

### 11. What happens if the user skips modules?
Skipped modules are excluded and the weights are renormalised over the assessed modules (e.g. password 20 % and
device 15 % become 57 % and 43 %). The score carries a coverage statement ("based on 2 of 5 modules — coverage 40 %")
and a "Partial assessment" badge below 60 % coverage. Chains that need a skipped module simply cannot fire.

---

### Likely follow-ups
* **"How did you choose 0.3 / 39 / 59?"** 0.3 is the configurable escalation factor (`ESCALATION_FACTOR`); 39 and 59
  are the tops of the CRITICAL and HIGH bands, so a CRITICAL/HIGH chain forces the overall tier. All are in
  `risk/chain_rules.py`, and the ablation shows the effect of the 59 cap.
* **"Isn't the critical floor arbitrary?"** It encodes a security principle: one exploitable critical path is enough;
  averaging good areas cannot compensate. CVSS takes a similar worst-case view.
* **"Could the test split leak into model selection?"** No — the RF/XGB and LR/RF choice is by F1 on the test split
  as specified, but the fusion method was chosen on out-of-fold training predictions only.
* **"Why did URL accuracy drop when you fixed the data?"** The 0.99 came from a shortcut (legit = bare homepages). A
  lower honest number is better than a high number that fails on wikipedia.org deep links.
