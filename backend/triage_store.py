"""Persisted human-on-the-loop triage state.

Findings/incidents are recomputed on every upload (server holds no session),
so the ONLY durable thing is the analyst's triage decision, keyed by the stable
incident fingerprint. On re-analysis we merge stored state back in by id.

File-backed JSON with a process-level lock and atomic replace. For durable
storage in the read-only production container, mount a volume and point
BLUEHOUND_TRIAGE_DB at it.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import triage as _triage

_DEFAULT_PATH = os.getenv(
    "BLUEHOUND_TRIAGE_DB",
    str(Path(tempfile.gettempdir()) / "bluehound" / "triage_state.json"),
)
_MAX_NOTE_LEN = 2000
_MAX_ANALYST_LEN = 120
_MAX_RECORDS = 50_000  # backstop against unbounded growth


class TriageStore:
    def __init__(self, path: str = _DEFAULT_PATH):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._cache: Optional[Dict[str, Dict[str, Any]]] = None

    # ── persistence ────────────────────────────────────────────
    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                data = {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            data = {}
        self._cache = data
        return data

    def _flush(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)  # atomic
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        self._cache = data

    # ── public API ─────────────────────────────────────────────
    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._load().get(incident_id, {})) or None

    def all(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._load().items()}

    def upsert(self, incident_id: str, *,
               status: Optional[str] = None,
               priority: Optional[str] = None,
               note: Optional[str] = None,
               analyst: Optional[str] = None,
               updated_at: str = "") -> Dict[str, Any]:
        """Apply a partial triage update; unspecified fields are preserved.
        Raises ValueError on invalid status/priority."""
        err = _triage.validate_triage_update(status, priority)
        if err:
            raise ValueError(err)
        with self._lock:
            data = self._load()
            if len(data) >= _MAX_RECORDS and incident_id not in data:
                raise ValueError("triage store is full")
            rec = dict(data.get(incident_id) or _triage.default_triage(priority or "P3"))
            if status is not None:
                rec["status"] = status
            if priority is not None:
                rec["priority"] = priority
            if note is not None:
                rec["note"] = str(note)[:_MAX_NOTE_LEN]
            if analyst is not None:
                rec["analyst"] = str(analyst)[:_MAX_ANALYST_LEN]
            rec["updated_at"] = updated_at or rec.get("updated_at", "")
            data[incident_id] = rec
            self._flush(data)
            return dict(rec)

    def merge_into_incidents(self, incidents: list) -> list:
        """Attach persisted triage state to freshly-computed incidents by id.
        Untriaged incidents get a default (status=new, priority=suggested)."""
        with self._lock:
            data = self._load()
        for inc in incidents:
            stored = data.get(inc["id"])
            if stored:
                inc["triage"] = {
                    "status": stored.get("status", _triage.STATUS_NEW),
                    "priority": stored.get("priority", inc["suggested_priority"]),
                    "note": stored.get("note", ""),
                    "analyst": stored.get("analyst", ""),
                    "updated_at": stored.get("updated_at", ""),
                    "excluded_findings": list(stored.get("excluded_findings", [])),
                }
            else:
                inc["triage"] = _triage.default_triage(inc["suggested_priority"])
            # Mark per-finding exclusions and recompute the active severity.
            excluded = set(inc["triage"].get("excluded_findings", []))
            for f in inc.get("findings", []):
                f["excluded"] = f.get("key") in excluded
            _triage.recompute_active(inc)
        return incidents

    def set_finding_excluded(self, incident_id: str, finding_key: str, excluded: bool,
                             suggested_priority: str = "P3", updated_at: str = "") -> Dict[str, Any]:
        """Exclude / re-include a single finding (event) within an incident chain."""
        with self._lock:
            data = self._load()
            rec = dict(data.get(incident_id) or _triage.default_triage(suggested_priority))
            ex = set(rec.get("excluded_findings", []))
            if excluded:
                ex.add(finding_key)
            else:
                ex.discard(finding_key)
            rec["excluded_findings"] = sorted(ex)
            rec["updated_at"] = updated_at or rec.get("updated_at", "")
            data[incident_id] = rec
            self._flush(data)
            return dict(rec)

    # test/maintenance helper
    def _reset(self) -> None:
        with self._lock:
            self._cache = {}
            try:
                if self.path.exists():
                    self.path.unlink()
            except OSError:
                pass
