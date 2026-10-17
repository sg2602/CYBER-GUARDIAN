"""SQLite persistence + security history.

PRIVACY: only scores, finding IDs and chain IDs are stored.  Raw inputs
(passwords, email text, URLs, manifests) and free-text evidence are NEVER written.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from utils.common import ROOT

DEFAULT_DB = ROOT / "database" / "cyberguardian.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    overall_score REAL,
    baseline_score REAL,
    risk_level TEXT,
    coverage REAL,
    password_score REAL,
    email_score REAL,
    url_score REAL,
    permission_score REAL,
    device_score REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    module TEXT NOT NULL,
    severity TEXT NOT NULL,
    points_lost REAL,
    source TEXT,
    attack_ids TEXT
);
CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    chain_id TEXT NOT NULL,
    severity TEXT
);
"""


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DEFAULT_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(SCHEMA)
    return con


def save_assessment(a: dict, db_path: str | Path | None = None) -> str:
    """Persist an assessment produced by risk.assessment.run_assessment (IDs and numbers only)."""
    mods = a["modules"]
    sc = lambda m: (None if not mods[m].get("assessed") else round(float(mods[m]["score"]), 2))
    with connect(db_path) as con:
        con.execute(
            "INSERT OR REPLACE INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (a["assessment_id"], a["created_at"],
             None if a["score"] is None else round(a["score"], 2),
             None if a["baseline"] is None else round(a["baseline"], 2),
             a["risk_level"], round(a["coverage"]["fraction"], 3),
             sc("password"), sc("email"), sc("url"), sc("permission"), sc("device")))
        con.execute("DELETE FROM findings WHERE assessment_id=?", (a["assessment_id"],))
        con.execute("DELETE FROM chains WHERE assessment_id=?", (a["assessment_id"],))
        rows = []
        for m, r in mods.items():
            if r.get("assessed"):
                for f in r["findings"]:
                    rows.append((a["assessment_id"], f["id"], m, f["severity"], round(f["points_lost"], 3),
                                 f["source"], ",".join(f["attack_ids"])))
        for f in a.get("correlation_findings", []):
            rows.append((a["assessment_id"], f["id"], "correlation", f["severity"], round(f["points_lost"], 3),
                         "correlation", ",".join(f["attack_ids"])))
        con.executemany("INSERT INTO findings (assessment_id, finding_id, module, severity, points_lost, source, attack_ids)"
                        " VALUES (?,?,?,?,?,?,?)", rows)
        con.executemany("INSERT INTO chains (assessment_id, chain_id, severity) VALUES (?,?,?)",
                        [(a["assessment_id"], c["id"], c["severity"]) for c in a.get("chains", [])])
    return a["assessment_id"]


def list_assessments(db_path: str | Path | None = None) -> list[dict]:
    with connect(db_path) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM assessments ORDER BY created_at, assessment_id")]


def get_findings(assessment_id: str, db_path: str | Path | None = None) -> list[dict]:
    with connect(db_path) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM findings WHERE assessment_id=? ORDER BY points_lost DESC",
                                             (assessment_id,))]


def get_chains(assessment_id: str, db_path: str | Path | None = None) -> list[dict]:
    with connect(db_path) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM chains WHERE assessment_id=?", (assessment_id,))]


def improvement(db_path: str | Path | None = None) -> float | None:
    """Score delta of the latest assessment vs the previous one."""
    rows = [r for r in list_assessments(db_path) if r["overall_score"] is not None]
    if len(rows) < 2:
        return None
    return rows[-1]["overall_score"] - rows[-2]["overall_score"]


def delete_all(db_path: str | Path | None = None):
    with connect(db_path) as con:
        con.executescript("DELETE FROM findings; DELETE FROM chains; DELETE FROM assessments;")
