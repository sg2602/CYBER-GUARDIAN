"""Build the processed training datasets from data/raw/.

    python data/prepare_datasets.py

Outputs
  data/url_dataset.csv    columns: url,label,source   (label 1 = phishing, 0 = legitimate)
  data/email_dataset.csv  columns: text,label,source  (label 1 = phishing/fraud, 0 = legitimate)

URL dataset = PhiUSIIL (balanced subsample) + PhishTank verified-online snapshot
(phishing) + ISCX-URL-2016 benign list (legitimate) + faizann24 malicious-URL
dataset (benign deep links + malicious URLs).  Mixing sources reduces the
well-known PhiUSIIL artefact where every legitimate URL is a bare https://www.
homepage (a model trained on PhiUSIIL alone learns "has a path => phishing").
Scheme-less / http-era benign URLs get a random http/https scheme (same rate
for both classes) so HTTPS is not a label shortcut.

Email dataset = Nazario phishing corpus + Nigerian-fraud corpus (positives) and
the legitimate ("ham") messages of SpamAssassin + CEAS-08 (negatives).  Spam
that is not phishing is excluded so that the label means "phishing/fraud".
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
SEED = 42


def _random_scheme(urls: pd.Series, rng: np.random.Generator, p_https: float = 0.5) -> pd.Series:
    """Prefix scheme-less URLs with http:// or https:// at random (same rate for both classes)."""
    schemes = np.where(rng.random(len(urls)) < p_https, "https://", "http://")
    return pd.Series(schemes, index=urls.index) + urls.str.replace(r"^[a-z]+://", "", regex=True)


def build_urls(per_class_phiusiil: int = 15000) -> pd.DataFrame:
    rng = np.random.default_rng(SEED)
    parts = []
    phi = pd.read_csv(RAW / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    # In PhiUSIIL label 1 = legitimate, 0 = phishing  -> invert to our convention
    phi = phi.rename(columns={"URL": "url"})
    phi["label"] = 1 - phi["label"]
    for lab in (0, 1):
        sub = phi[phi.label == lab]
        parts.append(sub.sample(min(per_class_phiusiil, len(sub)), random_state=SEED).assign(source="PhiUSIIL"))
    pt = pd.read_csv(RAW / "phishtank_online_valid.csv", usecols=["url"])
    parts.append(pt.assign(label=1, source="PhishTank-2020"))
    bn = pd.read_csv(RAW / "iscx_benign_urls.csv", header=None, names=["url"])
    bn = bn.sample(min(10000, len(bn)), random_state=SEED)
    # ISCX benign URLs were collected over http in 2016; the same sites serve https today.
    # Re-assign the scheme at random so that 'has_https' is not a label shortcut.
    bn["url"] = _random_scheme(bn["url"], rng)
    parts.append(bn.assign(label=0, source="ISCX-URL-2016-benign"))
    # faizann24 malicious-URL dataset: diverse benign deep links + malicious URLs, no scheme.
    fz = pd.read_csv(RAW / "faizann24_urls.csv")
    fz["label"] = (fz["label"] == "bad").astype(int)
    fz_good = fz[fz.label == 0].sample(20000, random_state=SEED)
    fz_bad = fz[fz.label == 1].sample(10000, random_state=SEED)
    for sub in (fz_good, fz_bad):
        sub = sub.copy()
        sub["url"] = _random_scheme(sub["url"].astype(str), rng)
        parts.append(sub.assign(source="faizann24-malicious-urls"))
    df = pd.concat(parts, ignore_index=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df.url.str.len() > 4].drop_duplicates("url").sample(frac=1, random_state=SEED).reset_index(drop=True)
    return df[["url", "label", "source"]]


def _clean(text: str, limit: int = 4000) -> str:
    text = str(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;|&amp;|&lt;|&gt;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def build_emails() -> pd.DataFrame:
    parts = []
    naz = pd.read_csv(RAW / "Nazario.csv")
    parts.append(naz.assign(label=1, source="Nazario"))
    nig = pd.read_csv(RAW / "Nigerian_Fraud.csv")
    parts.append(nig.sample(min(1500, len(nig)), random_state=SEED).assign(label=1, source="Nigerian_Fraud"))
    sa = pd.read_csv(RAW / "SpamAssasin.csv")
    parts.append(sa[sa.label == 0].assign(label=0, source="SpamAssassin-ham"))
    ceas = pd.read_csv(RAW / "CEAS_08.csv")
    ceas_ham = ceas[ceas.label == 0]
    parts.append(ceas_ham.sample(min(2000, len(ceas_ham)), random_state=SEED).assign(label=0, source="CEAS08-ham"))
    df = pd.concat(parts, ignore_index=True)
    df["text"] = ("Subject: " + df["subject"].fillna("").astype(str) + "\n" + df["body"].fillna("").astype(str)).map(_clean)
    df = df[df.text.str.len() > 20].drop_duplicates("text").sample(frac=1, random_state=SEED).reset_index(drop=True)
    return df[["text", "label", "source"]]


def main():
    u = build_urls()
    u.to_csv(HERE / "url_dataset.csv", index=False)
    print("url_dataset.csv", u.shape, u.label.value_counts().to_dict(), u.source.value_counts().to_dict())
    e = build_emails()
    e.to_csv(HERE / "email_dataset.csv", index=False)
    print("email_dataset.csv", e.shape, e.label.value_counts().to_dict(), e.source.value_counts().to_dict())


if __name__ == "__main__":
    main()
