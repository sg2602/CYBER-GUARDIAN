# 🛡️ CyberGuardian
### Intelligent Personal Cybersecurity Risk Assessment System
*An AI-Assisted Personal Cybersecurity Risk Assessment and Security Recommendation Platform*

Python · Streamlit · SQLite · scikit-learn · XGBoost · SHAP · Plotly · ReportLab — 2-person team, 14-day build.

---

## 1. Overview

CyberGuardian assesses five areas of a person's security — **password, email, website/URL, mobile-app permissions
and device** — and produces a **Cyber Safety Score (0–100, higher = safer)** with prioritised fixes.

What makes it different is *how it reasons about risk*:

> **Novelty statement.** CyberGuardian is a personal cybersecurity assessment platform whose risk engine models how
> weaknesses combine into attack chains, rather than scoring them independently. Its contributions are: (1) a
> cross-module Threat Correlation Engine with compound-risk escalation and critical-severity floors, mapped to MITRE
> ATT&CK; (2) a counterfactual What-If Remediation Simulator that ranks actions by risk reduction per unit of effort;
> (3) unified score traceability across rule-based and ML (SHAP) evidence; and (4) rule–ML disagreement surfaced as
> explicit uncertainty, plus assessment-coverage confidence. An India-localized phishing/scam rule set is included as
> an additional contribution.

**The problem.** A plain weighted average hides critical risk. In our scenario study (P02), a user with a good
password, good device and a clean app — but a live credential-harvesting email in their inbox — gets **65/100
(MODERATE)** from a weighted average. CyberGuardian scores the same profile **39 (CRITICAL)** because the email's own
login link is a working credential-harvest kit (chain `CH_CRED_HARVEST`).

| | Contribution | Where |
|---|---|---|
| **C1** | Threat Correlation Engine — attack chains, escalation, critical floor, ATT&CK | `risk/correlation_engine.py`, `risk/chain_rules.py` |
| **C2** | What-If Remediation Simulator — counterfactual re-scoring, gain ÷ effort ranking | `risk/whatif_simulator.py` |
| **C3** | Unified score traceability — every lost point traced to a rule / ML-SHAP / correlation finding | `risk/risk_engine.py` (+ unit test) |
| **C4** | Uncertainty layer — rule-vs-ML disagreement badge + coverage confidence | `utils/common.py`, `risk/risk_engine.py` |
| **C5** | India-localized scam rules — KYC, UPI collect, electricity, courier/customs, digital arrest, fake bank, Aadhaar/PAN, KBC | `utils/wordlists/india_scam_lexicon.json` |

We do **not** claim 100% accuracy, do not claim to "detect malicious websites" and did not invent phishing detection.
CyberGuardian *estimates URL-based security risk using structural, domain and ML-based indicators.*

---

## 2. Quick start

```bash
pip install -r requirements.txt
streamlit run app.py                 # open http://localhost:8501  -> "Load demo profile" for the story
```

Trained models, processed datasets, results and the tracker are already included. To reproduce **everything**
(download data → rebuild datasets → retrain → select fusion → all evaluations → tests):

```bash
./run_all.sh
```

Individual steps:

```bash
python data/download_data.py && python data/prepare_datasets.py   # only if data/*.csv are missing
python ml/train_url_model.py           # RF vs XGBoost -> ml/models/url_model.joblib
python ml/train_phishing_model.py      # LR vs RF      -> ml/models/phishing_model.joblib
python ml/select_fusion.py             # rule+ML fusion chosen on out-of-fold TRAINING data
python evaluation/run_scenario_study.py
python evaluation/adversarial_url_test.py
python evaluation/disagreement_stats.py
python evaluation/india_eval.py
python evaluation/run_test_suites.py
python -m pytest -q tests
python build_tracker.py                # regenerates CyberGuardian_Project_Tracker.xlsx from results/
```

---

## 3. Architecture

```text
                     ┌──────────────────────┐
                     │     Streamlit UI     │   app.py + pages/ (7 pages)
                     └──────────┬───────────┘
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
       Security Scanner   Recommendations     Risk Dashboard
              │              & What-If
   ┌──────────┼──────────┬──────────┬──────────┐
   ▼          ▼          ▼          ▼          ▼
Password    Email       URL      App Perm.   Device       modules/*.py
 Audit     Analysis   Scanner     Audit      Audit        (rules; email+URL also ML + SHAP)
   └──────────┴──────────┴──────────┴──────────┘
                         │  standard ModuleResult / Finding objects (utils/common.py)
                         ▼
              ┌──────────────────────────┐
              │ Threat Correlation Engine│  C1  chains · escalation · ATT&CK
              └────────────┬─────────────┘
                           ▼
              ┌──────────────────────────┐
              │ Risk Assessment Engine   │  weights renormalised · HIGH-chain cap ·
              │                          │  critical floor · coverage (C4) · breakdown (C3)
              └────────────┬─────────────┘
                           ▼
              Cyber Safety Score (0–100) + "points lost" breakdown
                           │
        ┌──────────────────┼───────────────────┐
        ▼                  ▼                   ▼
 Recommendation     What-If Simulator     Explainability
     Engine              (C2)            SHAP (ML) + rule reasons
        └──────────────────┼───────────────────┘
                           ▼
          Security Audit Report (HTML / PDF)  →  SQLite (IDs + scores only)  →  History & trend
```

### Shared data contract
Every module returns a `ModuleResult` with a list of `Finding`s (`id`, `module`, `title`, `severity`,
`points_lost`, `evidence`, `source` = rule|ml|correlation, `attack_ids`, `remediation_ids`).
Invariant (tested): **module score = 100 − Σ points_lost**.

Risk bands everywhere: **80–100 LOW · 60–79 MODERATE · 40–59 HIGH · 0–39 CRITICAL**.

---

## 4. Modules

| Module | Approach | Highlights |
|---|---|---|
| **Password** (`modules/password_audit.py`) | Rules | length & classes; pattern-penalised entropy; SecLists 10k common passwords (+ leetspeak); dictionary/names; repeats; keyboard/alpha/numeric sequences; Name+digits (`Samriddhi123` → HIGH); years; reuse flag. **Never stored**, and evidence never quotes the password. |
| **Email** (`modules/email_analyzer.py`) | Rules + ML | Headers (Reply-To mismatch, Return-Path, display-name spoofing, suspicious sender domain, SPF/DKIM/DMARC); content cues (urgency, threats, credential/financial requests, prizes, verify-account, call-back numbers, formatting); **India rules `EMAIL_IN_*`**; every embedded link runs through the URL module; TF-IDF + engineered features → Logistic Regression vs Random Forest. |
| **URL** (`modules/url_scanner.py`) | Rules + ML + SHAP | 22 lexical features (length, dots, subdomains, IP host, HTTPS, suspicious TLD, `@`, hyphens, digit ratio, shortener, punycode, brand look-alike via edit distance + digit swaps, brand outside real domain, sensitive keywords, port, `//` redirect, domain entropy…). Random Forest vs XGBoost; SHAP TreeExplainer. **Never fetches the URL.** Official brand domains get an allow-list (ML weight × 0.3). |
| **App permissions** (`modules/permission_audit.py`) | Rules + category baseline | Normal/Low/Medium/High/Critical severity table; expected permissions for 12 app categories; AndroidManifest.xml parser; "excessive for stated purpose" finding. |
| **Device** (`modules/device_audit.py`) | Questionnaire | 11 weighted YES/NO/Not-sure questions (weights sum to 100). "Not sure" = half risk and a separate `*_UNSURE` ID (does not trigger chains that need a definite NO). Not an antivirus. |

### Rule + ML fusion
The URL and email modules combine a **rule deficit** and an **ML deficit** (= probability × 100). The fusion method
(linear blend / max / noisy-OR) was chosen by `ml/select_fusion.py` using **5-fold out-of-fold predictions on the
training split only** (never the test split) and saved to `ml/models/fusion.json`:

* **URL → `max`** (either detector alone can raise the alarm) — OOF F1 0.871
* **Email → `linear`, 30% rules / 70% ML** — OOF F1 0.993

The fused deficit is split back into rule findings and one ML finding so the breakdown still reconciles exactly.

---

## 5. Threat Correlation Engine (C1) and risk formula

**Weights:** Password 20 % · Email 25 % · URL 25 % · Permissions 15 % · Device 15 % — renormalised over the modules
actually assessed.

```
weighted      = Σ w'_m · score_m                               (= baseline_score, the plain average)
penalties     = Σ correlation findings  (ESCALATION_FACTOR 0.3 × weighted deficit of the chain's findings,
                                         or more if needed to push a module into its target tier)
pre_floor     = weighted − penalties
HIGH-chain cap: any HIGH attack chain  → score ≤ 59
critical floor: any CRITICAL finding    → score ≤ 39
Cyber Safety Score = result;  100 − Σ(breakdown points) == score   (unit-tested to 1e-9)
```

| Chain | Fires when | ATT&CK | Effect |
|---|---|---|---|
| `CH_ACCOUNT_TAKEOVER` | weak/common/reused password **and** MFA = NO **and** (credential-phish email **or** malicious login URL) | T1566 → T1110, T1078 | CRITICAL → floor 39 |
| `CH_CRED_HARVEST` | phishing email (score ≤ 59) **and** its embedded link scored HIGH+ **and** login/verify/credential cues | T1566.002 | Email +1 tier; if that lands in CRITICAL the chain becomes CRITICAL |
| `CH_MOBILE_SURVEILLANCE` | ≥ 2 of SMS / mic / location / background location **and** at least one is unexpected for the category | T1429, T1430 | Permission → HIGH (+ HIGH-chain cap) |
| `CH_BANKING_TROJAN` | SMS + accessibility + overlay | T1417, T1411 | CRITICAL → floor 39 |
| `CH_UNRECOVERABLE` | no backup + no auto-updates + no disk encryption | T1486 | Device → HIGH (+ HIGH-chain cap) |
| `CH_INDIA_PAYMENT_SCAM` | `EMAIL_IN_UPI_COLLECT`/`EMAIL_IN_KYC` **and** risky link / call-back number / payment request | T1566, T1656 | Email → HIGH (+ HIGH-chain cap) |

Rules are data (`risk/chain_rules.py`) using a small recursive grammar (`finding` with wildcards, `all`, `any`,
`at_least`, `module_max`), so new chains need no code changes.

---

## 6. Privacy design ("no raw inputs stored")

* Passwords are analysed in memory and **never** written anywhere — not in SQLite, logs, session state (the form clears
  on submit), reports, or even finding evidence (no matched substrings).
* Email bodies, URLs and manifests are analysed in memory; SQLite stores **only scores, finding IDs, chain IDs,
  severities and ATT&CK IDs** (schema in `database/database.py`).
* URLs are never fetched or resolved.
* `tests/test_privacy_db_report.py` writes an assessment containing a secret password, URL and email-body marker,
  then asserts none of them appear in the raw bytes of the DB file or in the HTML report.

---

## 7. Machine-learning results (real runs, held-out 20 % stratified test sets)

Datasets are **real public datasets** (no synthetic data) — see `data/README.md` for sources, sizes and biases.

| Task | Model | Accuracy | Precision | Recall | F1 | Test n |
|---|---|---:|---:|---:|---:|---:|
| URL | **Random Forest (selected)** | 0.9050 | 0.8928 | 0.9064 | 0.8995 | 16,942 |
| URL | XGBoost | 0.9045 | 0.9036 | 0.8915 | 0.8975 | 16,942 |
| Email | **Logistic Regression (selected)** | 0.9929 | 0.9917 | 0.9869 | 0.9893 | 1,827 |
| Email | Random Forest | 0.9918 | 0.9869 | 0.9885 | 0.9877 | 1,827 |

URL data: PhiUSIIL + PhishTank + ISCX-URL-2016 benign + faizann24 (84,710 URLs).
Email data: Nazario + Nigerian-fraud (phishing) vs SpamAssassin + CEAS-08 ham (9,133 emails).
Confusion matrices: `results/confusion_*.png`. Source: `results/ml_metrics.csv`.

**Read with care:** the email score is high partly because phishing and legitimate mails come from different corpora
(style differences). The URL model initially scored ~0.99 because of a PhiUSIIL artefact (legit = bare homepages);
after fixing it (see `data/README.md`) the honest number is ~0.90. Precision and recall matter more than accuracy:
a false negative leaves the user exposed, a false positive erodes trust in the tool.

---

## 8. Novelty evidence (all produced by the scripts in `evaluation/`)

### 8.1 Scenario study — plain average vs correlation engine (`results/scenario_study.csv`, `.png`)
13 fictitious profiles; expected tiers were assigned **before** running the engine using the rubric
*"exploitable cross-module path to account takeover/fraud ⇒ CRITICAL; a single serious exposure or a HIGH chain ⇒ HIGH;
minor issues ⇒ MODERATE; none ⇒ LOW"*.

| | Plain weighted average | CyberGuardian |
|---|---:|---:|
| Exact tier agreement | 5 / 13 | **11 / 13** |
| Dangerous profiles (expected HIGH/CRITICAL) labelled LOW/MODERATE | 7 / 9 | **2 / 9** |
| Mean absolute tier error | 0.77 | **0.15** |
| Ablation: correlation *without* the HIGH-chain cap | — | 8 / 13 exact, 5 / 9 dangerous missed |

Examples: P02 credential-harvest phish 65 MODERATE → **39 CRITICAL**; P04 banking-trojan app 71 MODERATE → **39
CRITICAL**; P08 neglected device 75 MODERATE → **59 HIGH**. The two misses (P06 reused password + no MFA with no
observed lure; P13 "digital arrest" email alone) are documented limitations — no chain covers them.
*Honesty note:* the HIGH-chain cap was added after the first run of this study showed HIGH chains barely moved the
overall score; the ablation row keeps the original behaviour visible. The study is small and author-labelled — it
illustrates the mechanism, it is not a statistical claim.

### 8.2 Adversarial URL robustness (`results/adversarial_url_results.csv`, `.png`)
300 held-out phishing URLs per perturbation. Detection = HIGH+ (score < 60; ML p ≥ 0.5).

| Perturbation | Rules only | ML only | Hybrid | Hybrid flags MODERATE+ |
|---|---:|---:|---:|---:|
| original | 3.0 % | 93.0 % | **95.0 %** | 98.7 % |
| homoglyph swap | 3.3 % | 98.0 % | **100 %** | 100 % |
| prepend https | 1.7 % | 80.3 % | **83.3 %** | 90.3 % |
| URL shortener | 0 % | 100 % | 100 % | 100 % |
| long benign-looking path | 7.3 % | 47.0 % | **57.7 %** | 90.7 % |
| subdomain padding | 31.3 % | 100 % | 98.0 % | 100 % |

Findings: rules alone have very low recall on real phishing URLs (most are compromised sites, not brand look-alikes)
but they **help the hybrid on the hardest perturbation** (long benign path: 47 % → 58 %, and 91 % flagged at least
MODERATE). Prepending HTTPS hurts ML (93 → 80 %). The 100 % on shorteners is not a strength: the model flags short
random paths in general, including benign shortened links.

### 8.3 Rule–ML disagreement (`results/disagreement_stats.csv`)

| | URL (3,000 test URLs) | Email (1,827 test emails) |
|---|---:|---:|
| Disagreement (UNCERTAIN) rate | 47.6 % | 38.5 % |
| Hybrid error rate when UNCERTAIN | 15.3 % | 0.85 % |
| Hybrid error rate when not UNCERTAIN | 6.8 % | 0.62 % |
| Share of all hybrid errors that were flagged UNCERTAIN | 67 % | 46 % |
| ML correct when they disagree | 84.7 % | 99.3 % |

The flag does concentrate errors (URL errors are 2.2× more likely when flagged), but it fires far too often because
rule scores are not calibrated to these corpora — rules rarely reach the HIGH band on their own. Calibrating rule
scores is listed as future work.

### 8.4 India-localized test set (`evaluation/india_testset.csv`, 21 scams + 7 legitimate messages)

| Configuration | Scams detected | Legit falsely flagged |
|---|---:|---:|
| Hybrid **with** India rules | **81.0 %** | 57.1 % |
| Hybrid without India rules | 76.2 % | 57.1 % |
| Rules only **with** India rules | 52.4 % | **0 %** |
| Rules only without India rules | 38.1 % | 0 % |
| ML only | 61.9 % | 57.1 % |

The India rules add +14 points of recall to the rule layer at no false-positive cost. The ML model (trained on long
Western emails) transfers poorly to short Indian SMS-style messages — it flags legitimate OTP / delivery / Aadhaar
notices — which is exactly why CyberGuardian surfaces rule–ML disagreement instead of hiding it.

### 8.5 Tests
* **pytest: 73 passed** (`results/pytest_output.txt`) — every module, contract invariants, each chain firing *and not
  firing*, escalation factor, critical floor, HIGH-chain cap, weight renormalisation, breakdown reconciliation over
  every module subset, What-If gains/ranking, recommendations, privacy of DB + report, history delta, and all 7
  Streamlit pages rendered headless (empty and filled) plus scanner interactions.
* **Module test suites: 105 / 113 pass** (`results/test_cases.csv`) — password 24/25, email 23/25, URL 37/40,
  permissions 13/15, device 8/8. Failures are kept and explained in the tracker (e.g. lexical-ML false positives on
  stackoverflow/bbc deep links, both flagged UNCERTAIN).

---

## 9. Screenshots
See `docs/screenshots/`: home, scanner (URL with SHAP), risk dashboard (gauge, baseline-vs-correlated, attack chains,
waterfall), What-If simulator, report.

---

## 10. Design decisions (where the spec left a choice)
1. **Correlation points are in overall-score units**: `0.3 × Σ (renormalised weight × points)` of the participating findings.
2. **Disagreement** = one side scores ≥ 60 (safe side), the other < 60, and they are ≥ 20 points apart (a full tier).
3. **Raise-a-tier effects** that end in CRITICAL make the chain itself CRITICAL (so the floor applies) — this is what
   lets the problem-statement profile (P02) score CRITICAL.
4. **HIGH-chain cap at 59** generalises the critical floor to HIGH chains (see honesty note in 8.1).
5. **Fusion** chosen on out-of-fold training data, never the test set (`ml/select_fusion.py`).
6. **Allow-list** of official brand domains damps the URL ML estimate (× 0.3) — rules still apply.
7. Module risk tier comes from the module's points; a CRITICAL *finding* inside a module affects the *overall* score
   via the floor (so `Music app + device-admin` is a MODERATE module but caps the overall score at 39).
8. Streamlit navigation is declared in `app.py` with `st.navigation`, so the sidebar shows "Home" instead of "app".
9. Demo profile button on Home fills all five modules with the fictitious storyline for presentations.

## 11. Demo flow
1. Home → "Cyber Safety Score: Not yet assessed" → **Start Security Assessment**.
2. Password `Samriddhi123` → HIGH (name + digits). 3. Load phishing example (SBI KYC) → probability + reasons + SHAP.
4. Website → demo URL → CRITICAL, SHAP bars. 5. App permissions → Calculator with mic + SMS → privacy risk.
6. Device → demo answers (MFA = No, no backup). 7. Dashboard → **Account takeover** chain, score vs plain average.
8. Waterfall → where every point went. 9. What-If → tick MFA / password / email actions → projected score.
10. Report → Save → re-assess after fixes → History shows the improvement trend.
(Shortcut: **Load demo profile** on Home.)

## 12. Limitations
* URL analysis is lexical only (no page content); lexical ML produces false positives on unfamiliar legit deep links.
* Device audit is self-reported.
* Dataset bias: English/Western corpora from different years; corpus-style leakage inflates email accuracy.
* Rule scores are not calibrated, so the UNCERTAIN flag fires too often.
* Rules, brand lists and the India lexicon need maintenance; chains only cover the patterns we wrote.
* The scenario study is small and author-labelled.

## 13. Future work
Calibrate rule scores (isotonic regression) to make C4 sharper; content-based URL analysis in a sandbox; an
India-specific SMS dataset for ML; more chains (credential stuffing without a lure, coercion scams); per-user
history-aware chains; Android APK static analysis; Hindi/regional-language lexicons.

## 14. Team contributions
* **Me — Core Cybersecurity + Risk:** password audit, URL security, email analysis (incl. India rules), Threat
  Correlation Engine, risk engine, recommendation engine, What-If simulator, explainability, architecture, integration.
* **Teammate — Application + Data + Dashboard:** Streamlit UI, SQLite, permission audit, device audit, ML datasets &
  models, report generation, security history, dashboard visualisations, adversarial test harness.
* Git branches: `main`, `password-module`, `url-module`, `email-module`, `risk-engine`, `correlation-engine`,
  `dashboard`; merge via pull requests; bugs as Issues (see tracker "Bugs" sheet).

## 15. Project layout
```text
app.py  pages/  modules/  ml/ (models/, training, fusion)  risk/  explainability/  database/  reports/ (templates/)
utils/ (wordlists/)  data/  evaluation/ (test_suites/)  results/  tests/  docs/screenshots/
requirements.txt  run_all.sh  build_tracker.py  CyberGuardian_Project_Tracker.xlsx  VIVA_PREP.md
```

## 16. References
See the *Literature* sheet of `CyberGuardian_Project_Tracker.xlsx` (20 entries; items marked "verify" should be
checked before citing). Key ones: Lundberg & Lee 2017 (SHAP); Lundberg et al. 2020 (TreeExplainer); Strom et al. 2018
(MITRE ATT&CK); Ma et al. 2009 (lexical URL detection); Fette et al. 2007 (phishing email); Felt et al. 2011 and Enck
et al. 2009 (Android permissions); Sheyner et al. 2002 and Ou et al. 2005 (attack graphs); Wachter et al. 2017
(counterfactual explanations); Wheeler 2016 (zxcvbn); Prasad & Chandra 2024 (PhiUSIIL).
#   C Y B E R - G U A R D I A N  
 