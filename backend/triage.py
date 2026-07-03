"""Incident correlation + human-on-the-loop triage model.

LLM/rules lead (produce severity + a suggested priority); a human analyst then
flags each incident. This module is deterministic (testable); the narrative is
heuristic now and LLM-upgradeable via `narrative` without changing the schema.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

from time_utils import parse_ts, event_ts

# ── Severity → suggested fix priority (LLM/rules lead) ───────────────
#   P0 極高 / P1 高 / P2 中 / P3 低
SEVERITY_TO_PRIORITY = {
    "critical": "P0",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P3",
}
PRIORITY_LABELS = {"P0": "極高", "P1": "高", "P2": "中", "P3": "低"}
VALID_PRIORITIES = frozenset(SEVERITY_TO_PRIORITY.values())

# ── Human-on-the-loop status flags ──────────────────────────────────
STATUS_NEW          = "new"            # 未分流（預設）
STATUS_PENDING_FIX  = "pending_fix"    # 待修正風險
STATUS_REMEDIATED   = "remediated"     # 已修正風險
STATUS_EXCLUDED     = "excluded"       # 排除（誤報 / 不適用）
STATUS_RISK_ACCEPTED = "risk_accepted" # 接受風險
VALID_STATUSES = frozenset({
    STATUS_NEW, STATUS_PENDING_FIX, STATUS_REMEDIATED, STATUS_EXCLUDED, STATUS_RISK_ACCEPTED,
})
STATUS_LABELS = {
    STATUS_NEW: "未分流",
    STATUS_PENDING_FIX: "待修正風險",
    STATUS_REMEDIATED: "已修正風險",
    STATUS_EXCLUDED: "排除",
    STATUS_RISK_ACCEPTED: "接受風險",
}
# Statuses that remove an incident from the "open / actionable" queue.
CLOSED_STATUSES = frozenset({STATUS_REMEDIATED, STATUS_EXCLUDED, STATUS_RISK_ACCEPTED})

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "benign": 0}
DEFAULT_CORR_WINDOW_SECONDS = 3600


def severity_to_priority(severity: str) -> str:
    return SEVERITY_TO_PRIORITY.get((severity or "").lower(), "P3")


# Backwards-compatible alias — the shared implementation lives in time_utils.
# Kept so hunt_ir / tests that imported the underscored helper keep working.
_parse_ts = parse_ts


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _linked(a: Dict, b: Dict, window: int) -> bool:
    """Two findings on the SAME host are linked if they share a user, a process
    GUID, or occur within `window` seconds of each other."""
    if (a.get("hostname") or "") != (b.get("hostname") or ""):
        return False
    ua, ub = a.get("user_name") or "", b.get("user_name") or ""
    if ua and ua == ub:
        return True
    ga, gb = a.get("process_guid") or "", b.get("process_guid") or ""
    if ga and ga == gb:
        return True
    ta, tb = event_ts(a), event_ts(b)
    if ta is not None and tb is not None and abs(ta - tb) <= window:
        return True
    return False


def _incident_fingerprint(members: List[Dict]) -> str:
    """Stable id across re-uploads of the same data → triage state persists.
    Built only from member identity (no volatile fields like absolute time)."""
    keys = sorted(
        "|".join([
            str(m.get("rule_id", "")),
            str(m.get("hostname", "")),
            str(m.get("user_name", "")),
            str(m.get("process_guid", "")),
            str(m.get("commandline", ""))[:120],
        ])
        for m in members
    )
    digest = hashlib.sha1("\n".join(keys).encode("utf-8")).hexdigest()
    return "inc_" + digest[:16]


def _rollup_severity(members: List[Dict]) -> str:
    best = "low"
    for m in members:
        s = (m.get("severity") or "").lower()
        if _SEV_RANK.get(s, 0) > _SEV_RANK.get(best, 0):
            best = s
    return best.upper()


def _incident_title(members: List[Dict], host: str) -> str:
    tactics = [m.get("tactic") for m in members if m.get("tactic")]
    procs = [m.get("process_name") for m in members if m.get("process_name")]
    tactic = tactics[0] if tactics else "Suspicious activity"
    proc = f" via {procs[0]}" if procs else ""
    return f"{tactic} on {host or 'unknown host'}{proc}"


def _heuristic_narrative(members: List[Dict]) -> str:
    """Chronological one-line chain. Replace with an LLM call to upgrade to a
    full attack narrative without changing the incident schema."""
    ordered = sorted(members, key=lambda m: str(m.get("timestamp") or ""))
    steps = []
    for m in ordered[:8]:
        ts = str(m.get("timestamp") or "").replace("T", " ").replace("Z", "")
        steps.append(f"[{ts}] {m.get('rule_name', m.get('rule_id', '?'))}")
    chain = " → ".join(steps)
    extra = "" if len(ordered) <= 8 else f" (+{len(ordered) - 8} more)"
    return chain + extra


def correlate_findings(findings: List[Dict], window: int = DEFAULT_CORR_WINDOW_SECONDS) -> List[Dict]:
    """Group raw rule findings into correlated incidents.

    Host is a hard boundary; within a host, findings are clustered by shared
    user / process-GUID / time-proximity (union-find). Each incident gets a
    stable fingerprint, a rolled-up severity, and a suggested P0–P3 priority.
    """
    actionable = [f for f in (findings or []) if (f.get("severity") or "").lower() in _SEV_RANK and (f.get("severity") or "").lower() != "benign"]
    if not actionable:
        return []

    # Bucket by host first (hard boundary keeps unrelated hosts separate).
    by_host: Dict[str, List[Dict]] = {}
    for f in actionable:
        by_host.setdefault(f.get("hostname") or "unknown", []).append(f)

    incidents: List[Dict] = []
    for host, group in by_host.items():
        uf = _UnionFind(len(group))
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if _linked(group[i], group[j], window):
                    uf.union(i, j)
        clusters: Dict[int, List[Dict]] = {}
        for idx, f in enumerate(group):
            clusters.setdefault(uf.find(idx), []).append(f)

        for members in clusters.values():
            sev = _rollup_severity(members)
            tactic_ids = sorted({m.get("mitre") for m in members if m.get("mitre")})
            tactics = sorted({m.get("tactic") for m in members if m.get("tactic")})
            users = sorted({m.get("user_name") for m in members if m.get("user_name")})
            # Sort by parsed epoch (via event_ts) so mixed-format timestamps
            # order correctly; keep the raw string for display.
            ts_pairs = [(event_ts(m), str(m.get("timestamp") or "")) for m in members]
            ts_pairs = [(t, s) for t, s in ts_pairs if t is not None or s]
            if ts_pairs:
                # Sentinel keeps None values (unparseable) at the bounds without
                # crashing the compare.
                first_seen = min(ts_pairs, key=lambda p: (p[0] is None, p[0] if p[0] is not None else 0.0))[1]
                last_seen = max(ts_pairs, key=lambda p: (p[0] is None, p[0] if p[0] is not None else 0.0))[1]
            else:
                first_seen = last_seen = ""
            incidents.append({
                "id": _incident_fingerprint(members),
                "title": _incident_title(members, host),
                "severity": sev,
                "suggested_priority": severity_to_priority(sev),
                "tactic_ids": tactic_ids,
                "tactics": tactics,
                "hosts": [host],
                "users": users,
                "rule_ids": sorted({m.get("rule_id") for m in members if m.get("rule_id")}),
                "finding_count": len(members),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "narrative": _heuristic_narrative(members),
                "narrative_source": "heuristic",
                "findings": [_finding_summary(m) for m in members],
            })

    # Highest severity first, then most findings.
    incidents.sort(key=lambda inc: (_SEV_RANK.get(inc["severity"].lower(), 0), inc["finding_count"]), reverse=True)
    return incidents


def finding_key(f: Dict) -> str:
    """Stable per-finding id within an incident — lets the analyst exclude a
    single event in the attack chain (false positive) without affecting others."""
    blob = "|".join([
        str(f.get("rule_id", "")), str(f.get("hostname", "")), str(f.get("user_name", "")),
        str(f.get("process_guid", "")), str(f.get("commandline", ""))[:120],
        str(f.get("timestamp", "")),
    ])
    return "f_" + hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:14]


def _finding_summary(f: Dict) -> Dict:
    return {
        "key": finding_key(f),
        "rule_id": f.get("rule_id", ""),
        "rule_name": f.get("rule_name", ""),
        "severity": f.get("severity", ""),
        "mitre": f.get("mitre", ""),
        "process_name": f.get("process_name", ""),
        "hostname": f.get("hostname", ""),
        "user_name": f.get("user_name", ""),
        "timestamp": f.get("timestamp", ""),
        "commandline": (f.get("commandline") or "")[:500],
    }


def recompute_active(incident: Dict) -> None:
    """Recompute severity / priority / counts from non-excluded findings.
    Called after per-finding exclusions are merged in."""
    active = [f for f in incident.get("findings", []) if not f.get("excluded")]
    incident["active_finding_count"] = len(active)
    incident["all_excluded"] = (len(active) == 0 and len(incident.get("findings", [])) > 0)
    if active:
        sev = _rollup_severity(active)
        incident["severity"] = sev
        incident["suggested_priority"] = severity_to_priority(sev)


# ── Triage state validation / defaults ──────────────────────────────
def default_triage(suggested_priority: str) -> Dict[str, Any]:
    return {
        "status": STATUS_NEW,
        "priority": suggested_priority,
        "note": "",
        "analyst": "",
        "updated_at": "",
        "excluded_findings": [],
    }


def validate_triage_update(status: Optional[str], priority: Optional[str]) -> Optional[str]:
    """Return an error string if invalid, else None."""
    if status is not None and status not in VALID_STATUSES:
        return f"invalid status '{status}'"
    if priority is not None and priority not in VALID_PRIORITIES:
        return f"invalid priority '{priority}'"
    return None
