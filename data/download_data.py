"""Download the public datasets used by CyberGuardian into data/raw/.

    python data/download_data.py

All sources are public GitHub mirrors of public research datasets.  Check each
dataset's original licence/terms before redistribution.
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

RAW = Path(__file__).resolve().parent / "raw"

SOURCES = {
    # URL datasets
    "PhiUSIIL_Phishing_URL_Dataset.csv":
        "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv",
    "iscx_benign_urls.csv":
        "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/1.Benign_list_big_final.csv",
    "phishtank_online_valid.csv":
        "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/2.online-valid.csv",
    "faizann24_urls.csv":
        "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv",
    # Email datasets (curated phishing-email corpora)
    "Nazario.csv": "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/Nazario.csv",
    "Nigerian_Fraud.csv": "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/Nigerian_Fraud.csv",
    "SpamAssasin.csv": "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/SpamAssasin.csv",
    "CEAS_08.csv": "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/CEAS_08.csv",
    # Password list (SecLists)
    "../../utils/wordlists/common_passwords.txt":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
}


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    ok = True
    for name, url in SOURCES.items():
        dest = (RAW / name).resolve()
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[skip] {dest.name} already present")
            continue
        print(f"[get ] {url}")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"       -> {dest} ({dest.stat().st_size:,} bytes)")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"[FAIL] {name}: {e}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
