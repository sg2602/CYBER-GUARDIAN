"""Security Audit Report generation (HTML; PDF via reportlab when available).

The report contains only scores, finding titles/IDs, evidence summaries and
recommendations - never raw passwords, email bodies, full URLs or manifests.
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from risk.recommendation_engine import group_by_priority
from utils.common import MODULE_LABELS, MODULES, TIER_COLORS, TIER_LABELS

TEMPLATES = Path(__file__).resolve().parent / "templates"

FUTURE_RISK_HINTS = {
    "DEV_NO_AUTO_UPDATES": "Without automatic updates, newly published vulnerabilities will stay unpatched on this device.",
    "DEV_OS_OUTDATED": "An outdated OS accumulates known, exploitable vulnerabilities over time.",
    "DEV_NO_BACKUP": "Without backups, a future ransomware infection, theft or disk failure means permanent data loss.",
    "PERM_EXCESSIVE": "Apps with excessive permissions can silently start collecting more data after an update or ownership change.",
    "PWD_REUSED": "A breach at any site where this password is reused will expose this account (credential stuffing).",
    "DEV_NO_MFA": "Any future password leak or phishing success leads straight to account takeover while MFA is off.",
    "DEV_PUBLIC_WIFI_UNSAFE": "Logging in over open public Wi-Fi exposes sessions to interception on hostile networks.",
    "PERM_UNEXPECTED_BACKGROUND_LOCATION": "Background location allows continuous movement tracking.",
}
GENERAL_TIPS = [
    "Use a password manager and a unique passphrase for every account.",
    "Turn on MFA everywhere it is offered - start with email, banking and social media.",
    "Keep OS, browser and apps on automatic updates.",
    "Verify unexpected requests for money, OTPs or KYC through the official app or branch - never via links in messages.",
    "Review app permissions every few months; remove apps you no longer use.",
    "Keep an offline backup of important files.",
]


def _context(a: dict) -> dict:
    modules = []
    for m in MODULES:
        r = a["modules"][m]
        w = a["weights"].get(m)
        note = ""
        if r.get("uncertain"):
            note = "UNCERTAIN - rules and ML disagree, verify manually"
        eff = a.get("effective_module_scores", {}).get(m)
        if r.get("assessed") and eff is not None and eff < r["score"] - 1e-9:
            note = (note + "; " if note else "") + f"escalated by correlation to {eff:.0f}"
        modules.append({"label": MODULE_LABELS[m], "weight": f"{w:.0%}" if w else "-",
                        "score": f"{r['score']:.0f}" if r.get("assessed") else "skipped",
                        "risk": TIER_LABELS[r["risk_level"]] if r.get("assessed") else "-", "note": note})
    ids = {f["id"] for r in a["modules"].values() if r.get("assessed") for f in r["findings"]}
    future = [v for k, v in FUTURE_RISK_HINTS.items() if k in ids]
    uncertain = []
    for m in a.get("uncertain_modules", []):
        r = a["modules"][m]
        uncertain.append(f"{MODULE_LABELS[m]}: rule-based score {r['extra'].get('rule_score', 0):.0f} vs ML score "
                         f"{r['ml']['score']:.0f} - UNCERTAIN, verify manually.")
    return {"a": a, "modules": modules, "rec_groups": group_by_priority(a.get("recommendations", [])),
            "future": future, "uncertain": uncertain, "tips": GENERAL_TIPS,
            "total_lost": sum(b["points"] for b in a["breakdown"]),
            "color": lambda t: TIER_COLORS.get(t, "#616e7c"), "tier_label": lambda t: TIER_LABELS.get(t, "-")}


def render_html(a: dict) -> str:
    if a.get("score") is None:
        raise ValueError("Nothing assessed yet")
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(**_context(a))


def render_pdf(a: dict) -> bytes:
    """Compact PDF version (requires reportlab)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ctx = _context(a)
    st = getSampleStyleSheet()
    esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm, topMargin=1.5 * cm,
                            bottomMargin=1.5 * cm, title=f"CyberGuardian report {a['assessment_id']}")
    el = [Paragraph("CyberGuardian Security Audit Report", st["Title"]),
          Paragraph(f"Assessment {a['assessment_id']} &middot; {a['created_at']}", st["Normal"]), Spacer(1, 8),
          Paragraph(f"<b>Cyber Safety Score: {a['score']:.0f}/100 ({TIER_LABELS[a['risk_level']]})</b> - "
                    f"{a['coverage']['label']}. Plain weighted average: {a['baseline']:.0f}.", st["Normal"])]

    def table(rows, widths):
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e4e7eb")),
                               ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd2d9"))]))
        return t
    P = lambda s: Paragraph(esc(s), st["BodyText"])
    el += [Spacer(1, 8), Paragraph("Module scores", st["Heading2"]),
           table([["Module", "Weight", "Score", "Risk", "Notes"]] +
                 [[m["label"], m["weight"], m["score"], m["risk"], P(m["note"])] for m in ctx["modules"]],
                 [4.5 * cm, 1.6 * cm, 1.6 * cm, 2.2 * cm, 7.5 * cm])]
    el.append(Paragraph("Attack chains detected", st["Heading2"]))
    for c in a["chains"] or []:
        el.append(Paragraph(f"<b>{esc(c['name'])}</b> ({c['id']}, {c['severity']}; ATT&amp;CK {', '.join(c['attack_ids'])}): "
                            + esc(" -> ".join(c["steps"])), st["BodyText"]))
    if not a["chains"]:
        el.append(Paragraph("None detected.", st["BodyText"]))
    el += [Paragraph("Score breakdown (points lost)", st["Heading2"]),
           table([["Finding", "Source", "Points"]] + [[P(b["label"]), b["tag"], f"-{b['points']:.1f}"] for b in a["breakdown"]],
                 [11 * cm, 4 * cm, 2.4 * cm])]
    el.append(Paragraph("Recommendations", st["Heading2"]))
    for p, recs in ctx["rec_groups"].items():
        for r in recs:
            el.append(Paragraph(f"<b>[{p}] {esc(r['title'])}</b> (effort {r['effort']}) - " + esc(" ".join(r["steps"])),
                                st["BodyText"]))
    if a.get("whatif"):
        el += [Paragraph("What-If: best next actions", st["Heading2"]),
               table([["Action", "Effort", "New score", "Gain"]] +
                     [[P(w["title"]), w["effort"], f"{w['new_score']:.0f}", f"{w['gain']:+.0f}"] for w in a["whatif"][:8]],
                     [10 * cm, 2 * cm, 2.4 * cm, 2.4 * cm])]
    if ctx["uncertain"]:
        el.append(Paragraph("Needs manual verification", st["Heading2"]))
        el += [Paragraph(esc(u), st["BodyText"]) for u in ctx["uncertain"]]
    el += [Spacer(1, 10), Paragraph("Disclaimer: estimates only - lexical URL analysis, self-reported device answers, "
                                    "ML models trained on public datasets. No raw inputs are stored or included.", st["Italic"])]
    doc.build(el)
    return buf.getvalue()


def save_html(a: dict, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_html(a), encoding="utf-8")
    return path
