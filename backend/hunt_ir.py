"""FR-1: Hunt Query IR — schema validation + a deterministic, eval-only executor.

The LLM translates a natural-language question into this structured IR (never a
raw query string, CR-2). A deterministic executor then evaluates the IR against a
session's events — no `eval`, no dynamic query, only whitelisted fields and
pre-implemented operators (FR-1 安全). The same IR is also rendered to KQL/SPL/
Sigma via query_builder for the analyst's real SIEM (FR-1.4).

IR shape (v1 — `filter + after + same + within`; `sequence` is v2):

    {
      "version": 1,
      "description": "restatement of the question",
      "use_previous": false,                 # FR-1.5 conversational: scope to prior result
      "steps": [
        {"id": "a", "match": "all"|"any",
         "predicates": [{"field": <allowed>, "op": <allowed>, "value": ...}]},
        ...
      ],
      "relations": [
        {"type": "after",  "left": "a", "right": "b"},   # right occurs after left
        {"type": "same",   "field": "user_name"|"hostname"|"process_guid", "steps": ["a","b"]},
        {"type": "within", "seconds": 300, "steps": ["a","b"]}
      ],
      "select": "a"                          # which step's matched events to return
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from regex_safety import validate_user_regex, safe_search, reset_ir_regex_budget
from time_utils import event_ts as _ts

# Whitelisted event fields the IR may reference (normalized schema, ingest.py).
IR_FIELDS = frozenset({
    "process_name", "parent_process_name", "process_path", "commandline",
    "event_id", "user_name", "hostname", "source_ip", "destination_ip",
    "destination_port", "target_image", "target_object", "message",
    "properties", "process_guid", "event_outcome", "event_category",
    "action_type",
})
IR_OPS = frozenset({"eq", "ne", "contains", "regex", "in", "gte", "lte"})
SAME_FIELDS = frozenset({"user_name", "hostname", "process_guid", "source_ip"})
RELATION_TYPES = frozenset({"after", "same", "within"})

MAX_STEPS = 6
MAX_PREDICATES = 12
MAX_RELATIONS = 12
MAX_STEP_MATCHES = 5_000       # cap per-step candidate set for relation joins
MAX_RESULTS = 1_000            # cap returned event subset
MAX_VALUE_LEN = 2_048
MAX_IN_ITEMS = 50

# Time comparisons use the epoch stamp cached on each event by ingest — never
# the raw string, which misorders mixed-format data.


# ── Validation ──────────────────────────────────────────────────────────────
def validate_ir(raw: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Validate untrusted IR (from the LLM). Returns (ir, errors).

    Regex predicates are run through the ReDoS gate here so a malicious pattern
    is rejected before it ever touches event data.
    """
    errors: List[str] = []
    if not isinstance(raw, dict):
        return {}, ["root: IR must be an object"]

    # Fresh per-IR regex validation budget: caps the aggregate CPU an IR can
    # spend in the ReDoS timing gate even if every predicate is a regex.
    reset_ir_regex_budget()

    steps_in = raw.get("steps")
    if not isinstance(steps_in, list) or not steps_in:
        return {}, ["steps: at least one step required"]

    steps: List[Dict[str, Any]] = []
    seen_ids = set()
    for i, s in enumerate(steps_in[:MAX_STEPS]):
        if not isinstance(s, dict):
            errors.append(f"steps[{i}]: not an object")
            continue
        sid = str(s.get("id") or f"s{i}")[:32]
        if sid in seen_ids:
            sid = f"{sid}_{i}"
        seen_ids.add(sid)
        match_mode = s.get("match", "all")
        if match_mode not in ("all", "any"):
            match_mode = "all"
        preds: List[Dict[str, Any]] = []
        for p in (s.get("predicates") or [])[:MAX_PREDICATES]:
            if not isinstance(p, dict):
                continue
            field = str(p.get("field", ""))
            op = str(p.get("op", ""))
            if field not in IR_FIELDS:
                errors.append(f"steps[{i}]: field '{field[:40]}' not allowed")
                continue
            if op not in IR_OPS:
                errors.append(f"steps[{i}]: op '{op[:20]}' not allowed")
                continue
            value = p.get("value")
            if op == "in":
                if not isinstance(value, list):
                    errors.append(f"steps[{i}]: 'in' requires a list value")
                    continue
                value = [str(v)[:MAX_VALUE_LEN] for v in value[:MAX_IN_ITEMS]]
            elif op == "regex":
                rv = str(value)[:MAX_VALUE_LEN]
                ok, reason = validate_user_regex(rv)
                if not ok:
                    errors.append(f"steps[{i}]: regex rejected ({reason})")
                    continue
                value = rv
            else:
                value = str(value)[:MAX_VALUE_LEN] if value is not None else ""
            preds.append({"field": field, "op": op, "value": value})
        if not preds:
            errors.append(f"steps[{i}]: no valid predicates")
            continue
        steps.append({"id": sid, "match": match_mode, "predicates": preds})

    if not steps:
        return {}, errors or ["steps: no valid steps"]

    valid_ids = {s["id"] for s in steps}
    relations: List[Dict[str, Any]] = []
    for r in (raw.get("relations") or [])[:MAX_RELATIONS]:
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("type", ""))
        if rtype not in RELATION_TYPES:
            errors.append(f"relations: type '{rtype[:20]}' not allowed")
            continue
        if rtype == "after":
            left, right = str(r.get("left", "")), str(r.get("right", ""))
            if left not in valid_ids or right not in valid_ids or left == right:
                errors.append("relations.after: left/right must be distinct valid step ids")
                continue
            relations.append({"type": "after", "left": left, "right": right})
        elif rtype == "same":
            field = str(r.get("field", ""))
            rsteps = [str(x) for x in (r.get("steps") or [])]
            if field not in SAME_FIELDS:
                errors.append(f"relations.same: field '{field[:20]}' not allowed")
                continue
            if len(rsteps) != 2 or any(x not in valid_ids for x in rsteps) or rsteps[0] == rsteps[1]:
                errors.append("relations.same: needs two distinct valid step ids")
                continue
            relations.append({"type": "same", "field": field, "steps": rsteps})
        elif rtype == "within":
            try:
                seconds = int(r.get("seconds", 0))
            except (TypeError, ValueError):
                errors.append("relations.within: seconds must be an integer")
                continue
            seconds = max(1, min(seconds, 7 * 24 * 3600))
            rsteps = [str(x) for x in (r.get("steps") or [])]
            if len(rsteps) != 2 or any(x not in valid_ids for x in rsteps) or rsteps[0] == rsteps[1]:
                errors.append("relations.within: needs two distinct valid step ids")
                continue
            relations.append({"type": "within", "seconds": seconds, "steps": rsteps})

    select = str(raw.get("select", "")) or steps[-1]["id"]
    if select not in valid_ids:
        select = steps[-1]["id"]

    ir = {
        "version": 1,
        "description": str(raw.get("description", ""))[:1000],
        "use_previous": raw.get("use_previous") is True,
        "steps": steps,
        "relations": relations,
        "select": select,
    }
    return ir, errors


# ── Predicate evaluation (deterministic, whitelisted) ────────────────────────
def _field_value(ev: dict, field: str) -> str:
    return "" if ev.get(field) is None else str(ev.get(field))


def _eval_predicate(ev: dict, pred: dict) -> bool:
    field, op, value = pred["field"], pred["op"], pred["value"]
    actual = _field_value(ev, field)
    if op == "eq":
        return actual.lower() == str(value).lower()
    if op == "ne":
        return actual.lower() != str(value).lower()
    if op == "contains":
        return str(value).lower() in actual.lower()
    if op == "regex":
        return safe_search(value, actual)
    if op == "in":
        al = actual.lower()
        return any(al == str(v).lower() for v in value)
    if op in ("gte", "lte"):
        try:
            a, b = float(actual), float(value)
        except (TypeError, ValueError):
            return False
        return a >= b if op == "gte" else a <= b
    return False


def _eval_step(events: List[dict], step: dict) -> List[int]:
    """Return indices of events matching a step (bounded)."""
    preds = step["predicates"]
    all_mode = step["match"] == "all"
    out: List[int] = []
    reducer = all if all_mode else any
    for idx, ev in enumerate(events):
        if reducer(_eval_predicate(ev, p) for p in preds):
            out.append(idx)
            if len(out) >= MAX_STEP_MATCHES:
                break
    return out


# ── Executor ─────────────────────────────────────────────────────────────────
class HuntIRExecutor:
    """Deterministically evaluate a validated IR against a list of events."""

    def execute(self, ir: dict, events: List[dict],
                previous_idx: List[int] | None = None) -> Dict[str, Any]:
        # FR-1.5: scope the base event set to the previous result on follow-ups.
        if ir.get("use_previous") and previous_idx:
            allowed = set(previous_idx)
            base = [(i, ev) for i, ev in enumerate(events) if i in allowed]
        else:
            base = list(enumerate(events))

        # Match each step against the base set (carry original indices).
        base_events = [ev for _, ev in base]
        base_index_map = [i for i, _ in base]
        step_matches: Dict[str, List[int]] = {}   # step_id -> original indices
        for step in ir["steps"]:
            local = _eval_step(base_events, step)
            step_matches[step["id"]] = [base_index_map[li] for li in local]

        # Apply relations to constrain the SELECT step's candidate set.
        select = ir["select"]
        candidates = set(step_matches.get(select, []))

        for rel in ir["relations"]:
            candidates = self._apply_relation(rel, select, candidates, step_matches, events)
            if not candidates:
                break

        # Sort by parsed epoch (None → last). Never sort by the raw string.
        result_idx = sorted(
            candidates,
            key=lambda i: (_ts(events[i]) is None, _ts(events[i]) or 0.0),
        )
        result_idx = result_idx[:MAX_RESULTS]
        return {
            "result_idx": result_idx,
            "results": [events[i] for i in result_idx],
            "result_count": len(result_idx),
            "step_counts": {sid: len(idxs) for sid, idxs in step_matches.items()},
        }

    def _apply_relation(self, rel, select, candidates, step_matches, events) -> set:
        rtype = rel["type"]
        if rtype == "same":
            a, b = rel["steps"]
            if select not in (a, b):
                return candidates  # relation not about the select step
            other = b if select == a else a
            field = rel["field"]
            partner_vals = {
                str(events[i].get(field)) for i in step_matches.get(other, [])
                if events[i].get(field)
            }
            return {i for i in candidates
                    if events[i].get(field) and str(events[i].get(field)) in partner_vals}

        if rtype == "after":
            # right occurs after left → keep select events that have a partner.
            left, right = rel["left"], rel["right"]
            if select == right:
                partner_ts = sorted(
                    t for t in (_ts(events[i]) for i in step_matches.get(left, []))
                    if t is not None
                )
                if not partner_ts:
                    return set()
                earliest = partner_ts[0]
                return {i for i in candidates
                        if (_ts(events[i]) or -1) > earliest}
            if select == left:
                partner_ts = sorted(
                    t for t in (_ts(events[i]) for i in step_matches.get(right, []))
                    if t is not None
                )
                if not partner_ts:
                    return set()
                latest = partner_ts[-1]
                return {i for i in candidates
                        if (_ts(events[i]) or 1e18) < latest}
            return candidates

        if rtype == "within":
            a, b = rel["steps"]
            if select not in (a, b):
                return candidates
            other = b if select == a else a
            window = rel["seconds"]
            partner_ts = [t for t in (_ts(events[i]) for i in step_matches.get(other, []))
                          if t is not None]
            if not partner_ts:
                return set()
            partner_ts.sort()
            return {i for i in candidates if self._has_partner_within(
                _ts(events[i]), partner_ts, window)}

        return candidates

    @staticmethod
    def _has_partner_within(ts, sorted_partner_ts, window) -> bool:
        if ts is None:
            return False
        import bisect
        lo = bisect.bisect_left(sorted_partner_ts, ts - window)
        hi = bisect.bisect_right(sorted_partner_ts, ts + window)
        return hi > lo


# ── IR → query_builder filters (FR-1.4) ──────────────────────────────────────
def ir_to_filters(ir: dict) -> Dict[str, Any]:
    """Best-effort flatten of the SELECT step's predicates to QueryBuilder filters.

    The IR is richer than the flat filter model (temporal relations don't map to
    a single SIEM filter), so this exports the select step's field predicates —
    enough to give the analyst a runnable starting query in their SIEM.
    """
    field_map = {
        "process_name": "process_name",
        "hostname": "hostname",
        "user_name": "user_name",
        "source_ip": "source_ip",
        "destination_ip": "destination_ip",
        "event_id": "event_id",
    }

    def _filters_for(step: dict) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in step["predicates"]:
            f, op, v = p["field"], p["op"], p["value"]
            if f == "commandline":
                if op == "regex":
                    out["commandline_regex"] = v
                elif op != "ne":
                    out["commandline_contains"] = v if isinstance(v, str) else str(v)
            elif f in field_map and op in ("eq", "in"):
                out[field_map[f]] = v if op == "eq" else (v[0] if v else "")
        return out

    steps = ir.get("steps", [])
    select = ir.get("select")
    # Prefer the select step, but fall back to the first step that yields a usable
    # filter (a temporal IR's select step is often the generic consequence step).
    ordered = sorted(steps, key=lambda s: 0 if s["id"] == select else 1)
    for step in ordered:
        filters = _filters_for(step)
        if filters:
            return filters
    return {}
