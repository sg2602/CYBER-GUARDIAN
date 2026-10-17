#!/usr/bin/env bash
# Reproduce every number in README/results from scratch.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f data/url_dataset.csv ] || [ ! -f data/email_dataset.csv ]; then
  python data/download_data.py
  python data/prepare_datasets.py
fi
python ml/train_url_model.py
python ml/train_phishing_model.py
python ml/select_fusion.py
python evaluation/run_scenario_study.py
python evaluation/adversarial_url_test.py
python evaluation/disagreement_stats.py
python evaluation/india_eval.py
python evaluation/run_test_suites.py
python -m pytest -q tests | tee results/pytest_output.txt
