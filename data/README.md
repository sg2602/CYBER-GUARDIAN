# Data

**All ML results in this project come from REAL public datasets, not synthetic data.**
The processed datasets used for training are included (`url_dataset.csv`, `email_dataset.csv`) together with the
exact held-out test splits (`url_test_split.csv`, `email_test_split.csv`). The large raw files are *not* included
in the zip — re-download them with one command.

| File | Rows | Built from | Label |
|---|---:|---|---|
| `url_dataset.csv` | 84,710 | PhiUSIIL (15k + 15k sample), PhishTank verified-online snapshot (2020), ISCX-URL-2016 benign list (10k sample), faizann24 malicious-URL dataset (20k benign + 10k malicious sample) | 1 = phishing/malicious, 0 = legitimate |
| `email_dataset.csv` | 9,133 | Nazario phishing corpus + Nigerian-fraud corpus (positives); SpamAssassin ham + CEAS-08 ham sample (negatives) | 1 = phishing/fraud, 0 = legitimate |

Sources (public GitHub mirrors, fetched by `download_data.py`):
- PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024; UCI ML Repository id 967) — mirror: `elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL`
- PhishTank online-valid snapshot and ISCX-URL-2016 benign list — mirror: `shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques`
- Malicious-URL dataset — `faizann24/Using-machine-learning-to-detect-malicious-URLs`
- Phishing-email corpora (Nazario, Nigerian Fraud, SpamAssassin, CEAS-08) — mirror: `rokibulroni/Phishing-Email-Dataset`
- 10k most common passwords — SecLists (`danielmiessler/SecLists`)

Check each dataset's original licence/terms before redistributing.

## Rebuild from scratch (one command)

```bash
./run_all.sh            # downloads raw data if needed, rebuilds datasets, retrains, re-evaluates, runs tests
```

Or step by step:
```bash
python data/download_data.py      # -> data/raw/
python data/prepare_datasets.py   # -> data/url_dataset.csv, data/email_dataset.csv
python ml/train_url_model.py
python ml/train_phishing_model.py
python ml/select_fusion.py        # chooses rule+ML fusion on out-of-fold training data
```

## Drop in your own dataset

Any CSV works as long as it has the right columns:

```bash
python ml/train_url_model.py      --data path/to/urls.csv     # columns: url,label   (1 = phishing)
python ml/train_phishing_model.py --data path/to/emails.csv   # columns: text,label  (1 = phishing)
python ml/select_fusion.py
```

Metrics are rewritten to `results/ml_metrics.csv`, confusion matrices to `results/confusion_*.png`.

## Known dataset biases (read before quoting numbers)

- **PhiUSIIL legitimate URLs are bare `https://www.` homepages.** A lexical model trained on PhiUSIIL alone learns
  "has a path ⇒ phishing" and "https ⇒ legitimate" (we measured ~99% test accuracy and then saw it flag
  wikipedia/github deep links as phishing). We therefore mixed in benign deep links (ISCX, faizann24),
  gave scheme-less / 2016-era benign URLs a random http/https scheme (same rate for both classes), and
  normalised trailing slashes. Test accuracy dropped to ~0.90 — a more honest number.
- The email corpora are English, mostly 2000s-era Western mail. The model does **not** transfer well to short
  Indian SMS-style messages (see `results/india_testset_results.csv`) — that is why the India-localized rule set exists.
- Phishing and legitimate emails come from different corpora, so some separability is corpus style, not phishing
  content. Expect lower accuracy on your own inbox.
