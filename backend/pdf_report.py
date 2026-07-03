"""PDF session report — designed template built on top of ReportLab.

We deliberately do NOT use HTML/CSS-to-PDF here. The goal is a stable,
lightweight, deterministic layout that:

  * runs fully offline (no chromium, no font downloads, no network),
  * safely renders untrusted log strings (reportlab's Paragraph parser only
    accepts a tiny XML dialect — we pre-escape everything, and the values we
    emit are truncated so a hostile input cannot balloon the document),
  * fits the BlueHound visual identity (blue gradient title, dark cover panel,
    finding chips coloured by severity).

The public entry point is :func:`build_session_report`, which takes the same
in-memory analysis dict the API already returns and emits ``bytes``. The API
handler streams those bytes back as a file download.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer, Table,
    TableStyle, KeepTogether,
)

logger = logging.getLogger("bluehound.pdf")

# ── Brand palette ───────────────────────────────────────────────────────────
BRAND_PRIMARY = colors.HexColor("#0288d1")
BRAND_ACCENT = colors.HexColor("#4fc3f7")
BRAND_INK = colors.HexColor("#0f172a")     # dark ink for headings
INK_MUTED = colors.HexColor("#475569")
INK_SUBTLE = colors.HexColor("#94a3b8")
BG_PANEL = colors.HexColor("#f1f5f9")
BG_CARD = colors.HexColor("#ffffff")
BORDER = colors.HexColor("#cbd5e1")

SEV_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#ca8a04"),
    "low":      colors.HexColor("#2563eb"),
    "benign":   colors.HexColor("#16a34a"),
}
SEV_ORDER = ("critical", "high", "medium", "low", "benign")


# ── Helpers ─────────────────────────────────────────────────────────────────
def _escape_xml(text: Any) -> str:
    """Escape a value for ReportLab's mini-HTML Paragraph parser.

    Paragraph accepts a very small XML dialect. Any user-supplied log string
    could contain ``<`` or ``&`` and either crash the parser or (much worse)
    inject styling; we normalise those to entities before we ever hand text
    to a Paragraph. Length is capped separately by the caller.
    """
    if text is None:
        return ""
    s = str(text)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )


def _clip(text: Any, limit: int) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[: max(0, limit - 1)] + "…"


def _sev_color(severity: str) -> colors.Color:
    return SEV_COLORS.get((severity or "").lower(), INK_MUTED)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ── Styles ──────────────────────────────────────────────────────────────────
def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    S: Dict[str, ParagraphStyle] = {}
    S["title"] = ParagraphStyle(
        "BHTitle", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=26, leading=30, textColor=colors.whitesmoke, alignment=TA_LEFT,
        spaceAfter=6,
    )
    S["subtitle"] = ParagraphStyle(
        "BHSubtitle", parent=base["Normal"], fontName="Helvetica",
        fontSize=12, textColor=colors.HexColor("#dbeafe"), alignment=TA_LEFT,
    )
    S["h1"] = ParagraphStyle(
        "BHH1", parent=base["Heading1"], fontName="Helvetica-Bold",
        fontSize=16, leading=20, textColor=BRAND_INK,
        spaceBefore=4, spaceAfter=6,
    )
    S["h2"] = ParagraphStyle(
        "BHH2", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=17, textColor=BRAND_PRIMARY,
        spaceBefore=8, spaceAfter=4,
    )
    S["h3"] = ParagraphStyle(
        "BHH3", parent=base["Heading3"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=BRAND_INK,
        spaceBefore=6, spaceAfter=2,
    )
    S["body"] = ParagraphStyle(
        "BHBody", parent=base["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=13, textColor=BRAND_INK,
    )
    S["muted"] = ParagraphStyle(
        "BHMuted", parent=base["BodyText"], fontName="Helvetica",
        fontSize=8.5, leading=11.5, textColor=INK_MUTED,
    )
    S["mono"] = ParagraphStyle(
        "BHMono", parent=base["BodyText"], fontName="Courier",
        fontSize=8, leading=10.5, textColor=BRAND_INK,
    )
    S["kv_key"] = ParagraphStyle(
        "BHKvKey", parent=base["BodyText"], fontName="Helvetica-Bold",
        fontSize=9, leading=12, textColor=INK_MUTED,
    )
    S["kv_val"] = ParagraphStyle(
        "BHKvVal", parent=base["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=12, textColor=BRAND_INK,
    )
    S["cover_stat_num"] = ParagraphStyle(
        "BHCoverStatNum", parent=base["BodyText"], fontName="Helvetica-Bold",
        fontSize=22, leading=24, textColor=colors.whitesmoke, alignment=TA_CENTER,
    )
    S["cover_stat_lbl"] = ParagraphStyle(
        "BHCoverStatLbl", parent=base["BodyText"], fontName="Helvetica",
        fontSize=9, leading=11, textColor=colors.HexColor("#dbeafe"), alignment=TA_CENTER,
    )
    return S


# ── Page frame: gradient header + footer with page numbers ─────────────────
def _draw_page_chrome(canvas: Canvas, doc: BaseDocTemplate) -> None:
    """Header brand strip and footer page number on EVERY page."""
    w, h = A4
    canvas.saveState()
    # Header strip
    canvas.setFillColor(BRAND_INK)
    canvas.rect(0, h - 1.6 * cm, w, 1.6 * cm, fill=1, stroke=0)
    # Brand mark (simple stylised node graph)
    cx, cy = 1.3 * cm, h - 0.8 * cm
    canvas.setFillColor(BRAND_ACCENT)
    canvas.circle(cx, cy, 0.18 * cm, fill=1, stroke=0)
    canvas.circle(cx - 0.28 * cm, cy - 0.22 * cm, 0.11 * cm, fill=1, stroke=0)
    canvas.circle(cx + 0.28 * cm, cy - 0.22 * cm, 0.11 * cm, fill=1, stroke=0)
    canvas.setStrokeColor(BRAND_ACCENT)
    canvas.setLineWidth(0.6)
    canvas.line(cx, cy - 0.05 * cm, cx - 0.28 * cm, cy - 0.19 * cm)
    canvas.line(cx, cy - 0.05 * cm, cx + 0.28 * cm, cy - 0.19 * cm)
    # Wordmark
    canvas.setFont("Helvetica-Bold", 11)
    canvas.setFillColor(colors.whitesmoke)
    canvas.drawString(2.0 * cm, h - 0.95 * cm, "BlueHound")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#93c5fd"))
    canvas.drawString(4.1 * cm, h - 0.95 * cm, "Threat Hunt Report")
    # Right-aligned generation timestamp
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#cbd5e1"))
    canvas.drawRightString(w - 1.3 * cm, h - 0.95 * cm, doc._bh_generated_at)

    # Footer separator + page number
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(1.3 * cm, 1.3 * cm, w - 1.3 * cm, 1.3 * cm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(INK_MUTED)
    canvas.drawString(1.3 * cm, 0.85 * cm, "Generated by BlueHound · Confidential")
    canvas.drawRightString(w - 1.3 * cm, 0.85 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Section builders ────────────────────────────────────────────────────────
def _cover_hero(styles: Dict[str, ParagraphStyle], analysis: Dict[str, Any]) -> List[Any]:
    """The blue gradient panel at the top of page 1."""
    stats = analysis.get("finding_severity_counts") or {}
    sev_cells = []
    for sev in SEV_ORDER[:-1]:  # skip benign on cover
        n = int(stats.get(sev, 0) or 0)
        sev_cells.append([
            Paragraph(str(n), styles["cover_stat_num"]),
            Paragraph(sev.capitalize(), styles["cover_stat_lbl"]),
        ])
    # Layout: title on top, sev tiles below in a flat table.
    title_tbl = Table(
        [
            [Paragraph("BlueHound Threat Hunt Report", styles["title"])],
            [Paragraph(f"Dataset session · {analysis.get('event_count', 0):,} events "
                       f"· {analysis.get('finding_count', 0)} findings", styles["subtitle"])],
        ],
        colWidths=[17.4 * cm],
    )
    title_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BRAND_PRIMARY),
        ("BOX", (0, 0), (-1, -1), 0, BRAND_PRIMARY),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))

    stats_tbl = Table(
        [[cell[0] for cell in sev_cells], [cell[1] for cell in sev_cells]],
        colWidths=[17.4 * cm / 4] * 4,
        rowHeights=[0.9 * cm, 0.6 * cm],
    )
    stats_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BRAND_INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        # Individual coloured underlines under each severity number
        ("LINEBELOW", (0, 0), (0, 0), 1.4, SEV_COLORS["critical"]),
        ("LINEBELOW", (1, 0), (1, 0), 1.4, SEV_COLORS["high"]),
        ("LINEBELOW", (2, 0), (2, 0), 1.4, SEV_COLORS["medium"]),
        ("LINEBELOW", (3, 0), (3, 0), 1.4, SEV_COLORS["low"]),
    ]))
    return [title_tbl, stats_tbl, Spacer(1, 0.35 * cm)]


def _executive_summary(styles, analysis: Dict[str, Any]) -> List[Any]:
    stats = analysis.get("finding_severity_counts") or {}
    inc_total = analysis.get("incident_count") or len(analysis.get("incidents", []) or [])
    prescan = analysis.get("llm_prescan") or {}
    report = (prescan.get("report") or {}) if isinstance(prescan, dict) else {}
    overall = report.get("overall_severity") or _rollup(stats)
    phases = ", ".join((prescan.get("execute") or {}).get("attack_phases", [])) or "—"

    rows = [
        [Paragraph("Overall Severity", styles["kv_key"]),
         Paragraph(f'<font color="{_sev_color(overall).hexval()}"><b>{_escape_xml(str(overall).upper())}</b></font>',
                   styles["kv_val"])],
        [Paragraph("Events Analysed", styles["kv_key"]),
         Paragraph(f'{analysis.get("event_count", 0):,}'
                   + (" (truncated)" if analysis.get("events_truncated") else ""),
                   styles["kv_val"])],
        [Paragraph("Deterministic Findings", styles["kv_key"]),
         Paragraph(str(analysis.get("finding_count", 0)), styles["kv_val"])],
        [Paragraph("Correlated Incidents", styles["kv_key"]),
         Paragraph(str(inc_total), styles["kv_val"])],
        [Paragraph("Suspected Attack Phases", styles["kv_key"]),
         Paragraph(_escape_xml(_clip(phases, 200)), styles["kv_val"])],
        [Paragraph("Session ID", styles["kv_key"]),
         Paragraph(_escape_xml(_clip(analysis.get("session_id", "—"), 80)), styles["kv_val"])],
    ]
    kv = Table(rows, colWidths=[4.5 * cm, 12.9 * cm])
    kv.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, BORDER),
    ]))

    story: List[Any] = [Paragraph("Executive Summary", styles["h1"]), kv, Spacer(1, 0.3 * cm)]

    # Optional LLM narrative
    llm_summary = analysis.get("llm_summary") or {}
    if isinstance(llm_summary, dict):
        exec_txt = llm_summary.get("executive_summary")
        narrative = llm_summary.get("attack_narrative")
        if exec_txt:
            story.append(Paragraph("Analyst Summary", styles["h2"]))
            story.append(Paragraph(_escape_xml(_clip(exec_txt, 1500)), styles["body"]))
        if narrative:
            story.append(Paragraph("Attack Narrative", styles["h3"]))
            story.append(Paragraph(_escape_xml(_clip(narrative, 3000)), styles["body"]))
    return story


def _rollup(stats: Dict[str, int]) -> str:
    for sev in SEV_ORDER:
        if int(stats.get(sev, 0) or 0) > 0:
            return sev
    return "clean"


def _severity_breakdown(styles, analysis: Dict[str, Any]) -> List[Any]:
    stats = analysis.get("finding_severity_counts") or {}
    total = sum(int(stats.get(s, 0) or 0) for s in SEV_ORDER)
    header = ["Severity", "Count", "Share"]
    rows = [header]
    for sev in SEV_ORDER:
        n = int(stats.get(sev, 0) or 0)
        share = f"{(n / total * 100):.1f}%" if total else "0.0%"
        rows.append([sev.capitalize(), str(n), share])
    tbl = Table(rows, colWidths=[5 * cm, 3 * cm, 3 * cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 9.5),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_PANEL]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]
    # Colour a swatch on the severity name.
    for i, sev in enumerate(SEV_ORDER, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), _sev_color(sev)))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    tbl.setStyle(TableStyle(style))
    return [Paragraph("Finding Severity Breakdown", styles["h1"]), tbl, Spacer(1, 0.35 * cm)]


def _incidents_section(styles, analysis: Dict[str, Any]) -> List[Any]:
    incidents = analysis.get("incidents") or []
    if not incidents:
        return [Paragraph("Incidents", styles["h1"]),
                Paragraph("No correlated incidents in this session.", styles["muted"]),
                Spacer(1, 0.3 * cm)]

    story: List[Any] = [Paragraph("Correlated Incidents", styles["h1"]),
                        Paragraph(f"{len(incidents)} incident(s), sorted by severity.", styles["muted"]),
                        Spacer(1, 0.15 * cm)]

    for i, inc in enumerate(incidents[:20], start=1):
        story.append(_incident_card(styles, i, inc))
        story.append(Spacer(1, 0.2 * cm))
    if len(incidents) > 20:
        story.append(Paragraph(f"…and {len(incidents) - 20} more incident(s) omitted from PDF.", styles["muted"]))
    return story


def _incident_card(styles, idx: int, inc: Dict[str, Any]) -> Any:
    sev = (inc.get("severity") or "").lower()
    sev_col = _sev_color(sev)
    header_bits = [
        f'<font color="{sev_col.hexval()}"><b>{_escape_xml(sev.upper() or "?")}</b></font>',
        f'<font color="{INK_MUTED.hexval()}">Priority {_escape_xml(inc.get("suggested_priority") or "—")}</font>',
        f'<b>{_escape_xml(_clip(inc.get("title") or "Incident", 140))}</b>',
    ]
    head = Paragraph(" · ".join(header_bits), styles["h3"])

    meta_rows = [
        ["Hosts",   _escape_xml(_clip(", ".join(inc.get("hosts") or []), 200)) or "—"],
        ["Users",   _escape_xml(_clip(", ".join(inc.get("users") or []), 200)) or "—"],
        ["MITRE",   _escape_xml(_clip(", ".join(inc.get("tactic_ids") or []), 200)) or "—"],
        ["Tactics", _escape_xml(_clip(", ".join(inc.get("tactics") or []), 200)) or "—"],
        ["Window",  _escape_xml(_clip(f"{inc.get('first_seen', '')} → {inc.get('last_seen', '')}", 200))],
        ["Findings", str(inc.get("finding_count", len(inc.get("findings") or [])))],
    ]
    meta_tbl = Table(
        [[Paragraph(k, styles["kv_key"]), Paragraph(v, styles["kv_val"])] for k, v in meta_rows],
        colWidths=[2.5 * cm, 14.9 * cm],
    )
    meta_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]))

    narrative = _clip(inc.get("narrative") or "", 800)
    narr_para = Paragraph(_escape_xml(narrative), styles["body"]) if narrative else None

    # Attack chain preview (active-only, capped)
    chain_findings = [f for f in (inc.get("findings") or []) if not f.get("excluded")][:6]
    chain_rows = [["#", "Sev", "Rule", "Process / Host", "Time"]]
    for j, f in enumerate(chain_findings, start=1):
        chain_rows.append([
            str(j),
            (f.get("severity") or "").upper()[:4],
            _clip(f.get("rule_name") or f.get("rule_id") or "?", 42),
            _clip(f"{f.get('process_name') or '?'} @ {f.get('hostname') or '?'}", 40),
            _clip((f.get("timestamp") or "").replace("T", " ").replace("Z", ""), 22),
        ])
    chain_tbl = Table(chain_rows, colWidths=[0.8*cm, 1.3*cm, 5.5*cm, 6.3*cm, 3.5*cm])
    chain_style = [
        ("BACKGROUND", (0, 0), (-1, 0), BG_PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK_MUTED),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for row_idx in range(1, len(chain_rows)):
        sev_i = chain_findings[row_idx - 1].get("severity", "").lower()
        chain_style.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), _sev_color(sev_i)))
        chain_style.append(("FONTNAME", (1, row_idx), (1, row_idx), "Helvetica-Bold"))
    chain_tbl.setStyle(TableStyle(chain_style))

    body = [head, meta_tbl, Spacer(1, 0.15 * cm)]
    if narr_para:
        body.append(narr_para)
        body.append(Spacer(1, 0.15 * cm))
    body.append(chain_tbl)

    # Wrap the whole card in a bordered outer table so it survives page breaks
    # as a coherent block.
    card = Table([[body]], colWidths=[17.4 * cm])
    card.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LINEABOVE", (0, 0), (-1, 0), 2, sev_col),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
    ]))
    return KeepTogether(card)


def _top_findings_section(styles, analysis: Dict[str, Any]) -> List[Any]:
    findings = analysis.get("findings") or []
    if not findings:
        return []
    # Rank by severity, then by presence of command line for signal-to-noise.
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    top = sorted(findings, key=lambda f: (rank.get((f.get("severity") or "").lower(), 99),
                                          -len(f.get("commandline") or "")))[:15]

    story: List[Any] = [Paragraph("Top Findings", styles["h1"]),
                        Paragraph("Highest-severity deterministic detections in this session.", styles["muted"]),
                        Spacer(1, 0.15 * cm)]
    rows = [["Sev", "Rule", "MITRE", "Host / User", "CommandLine"]]
    for f in top:
        rows.append([
            (f.get("severity") or "").upper()[:4],
            _clip(f.get("rule_name") or f.get("rule_id") or "?", 30),
            _clip(f.get("mitre") or "—", 12),
            _clip(f"{f.get('hostname') or '?'} / {f.get('user_name') or '?'}", 26),
            _clip(f.get("commandline") or "", 60),
        ])
    tbl = Table(rows, colWidths=[1.2*cm, 4.5*cm, 1.9*cm, 4.0*cm, 5.8*cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("FONTNAME", (4, 1), (4, -1), "Courier"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_PANEL]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for row_idx, f in enumerate(top, start=1):
        sev_i = (f.get("severity") or "").lower()
        style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), _sev_color(sev_i)))
        style.append(("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"))
    tbl.setStyle(TableStyle(style))
    story.append(tbl)
    story.append(Spacer(1, 0.35 * cm))
    return story


def _hypotheses_section(styles, analysis: Dict[str, Any]) -> List[Any]:
    hyps = (analysis.get("hypotheses") or [])
    if not hyps:
        return []
    story = [Paragraph("Hunt Hypotheses", styles["h1"]),
             Paragraph(f"{len(hyps)} suspected lead(s) ranked by confidence.", styles["muted"]),
             Spacer(1, 0.15 * cm)]
    for h in hyps[:10]:
        conf_pct = int(round(float(h.get("confidence") or 0) * 100))
        title = _escape_xml(_clip(h.get("hypothesis") or "", 200))
        mitre = ", ".join(h.get("mitre") or [])
        hosts = ", ".join((h.get("entities") or {}).get("hosts") or [])
        users = ", ".join((h.get("entities") or {}).get("users") or [])
        head = Paragraph(f'<b>{conf_pct}%</b> · {title}', styles["h3"])
        kv = [
            ["Rationale", _escape_xml(_clip(h.get("rationale") or "—", 400))],
            ["MITRE",     _escape_xml(mitre or "—")],
            ["Hosts",     _escape_xml(hosts or "—")],
            ["Users",     _escape_xml(users or "—")],
            ["Evidence",  f"{int(h.get('evidence_count') or 0)} matching event(s)"],
        ]
        tbl = Table(
            [[Paragraph(k, styles["kv_key"]), Paragraph(v, styles["kv_val"])] for k, v in kv],
            colWidths=[2.5 * cm, 14.9 * cm],
        )
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        card = Table([[[head, tbl]]], colWidths=[17.4 * cm])
        card.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether(card))
        story.append(Spacer(1, 0.2 * cm))
    return story


# ── Public entry point ─────────────────────────────────────────────────────
def build_session_report(analysis: Dict[str, Any],
                         *, generated_at: Optional[str] = None,
                         requested_by: Optional[str] = None) -> bytes:
    """Render an analysis dict into a designed PDF report and return the bytes."""
    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.3 * cm, rightMargin=1.3 * cm,
        topMargin=2.0 * cm, bottomMargin=1.6 * cm,
        title="BlueHound Threat Hunt Report",
        author="BlueHound",
        subject="Session threat-hunt findings",
        creator="BlueHound PDF Reporter",
    )
    doc._bh_generated_at = generated_at or _now_iso()
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="chrome", frames=[frame],
                                       onPage=_draw_page_chrome)])

    styles = _build_styles()
    story: List[Any] = []
    story.extend(_cover_hero(styles, analysis))
    if requested_by:
        story.append(Paragraph(
            f"Requested by <b>{_escape_xml(_clip(requested_by, 60))}</b>",
            styles["muted"],
        ))
        story.append(Spacer(1, 0.2 * cm))
    story.extend(_executive_summary(styles, analysis))
    story.extend(_severity_breakdown(styles, analysis))
    story.extend(_incidents_section(styles, analysis))
    story.append(PageBreak())
    story.extend(_top_findings_section(styles, analysis))
    story.extend(_hypotheses_section(styles, analysis))

    doc.build(story)
    return buf.getvalue()
