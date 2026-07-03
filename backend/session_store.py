"""Bounded, TTL'd server-side event cache for FR-1/FR-2 hunt execution.

BlueHound is otherwise stateless (events are parsed, analyzed, and shipped back
to the browser). The natural-language hunt (FR-1) and the hypothesis validator
(FR-2) need to re-evaluate a structured IR against a session's events on the
server, so we keep a *bounded* cache here:

  - at most MAX_SESSIONS sessions (LRU eviction of the oldest),
  - at most MAX_EVENTS_PER_SESSION events per session,
  - each session expires after TTL_SECONDS of inactivity.

Stored events have `_raw` stripped (CR / `_strip_raw` parity) so the cache never
holds the original upload blob. This is in-process only; restart clears it.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

MAX_SESSIONS = int(os.getenv("BLUEHOUND_MAX_SESSIONS", "8"))
MAX_EVENTS_PER_SESSION = int(os.getenv("BLUEHOUND_MAX_SESSION_EVENTS", "50000"))
TTL_SECONDS = int(os.getenv("BLUEHOUND_SESSION_TTL", "3600"))


def _strip_raw(events: List[dict]) -> List[dict]:
    """Drop the internal `_raw` field before caching (parity with main._strip_raw)."""
    return [{k: v for k, v in ev.items() if k != "_raw"} for ev in events]


class SessionStore:
    def __init__(self, ttl_seconds: int = TTL_SECONDS,
                 max_sessions: int = MAX_SESSIONS,
                 max_events: int = MAX_EVENTS_PER_SESSION):
        self.ttl = ttl_seconds
        self.max_sessions = max_sessions
        self.max_events = max_events
        self._lock = threading.Lock()
        # session_id -> {"events": [...], "created": ts, "accessed": ts}
        self._store: Dict[str, Dict[str, Any]] = {}

    def _now(self) -> float:
        return time.monotonic()

    def _evict_expired(self) -> None:
        now = self._now()
        for sid in [s for s, rec in self._store.items() if now - rec["accessed"] > self.ttl]:
            self._store.pop(sid, None)

    def put(self, events: List[dict], session_id: Optional[str] = None,
            findings: Optional[List[dict]] = None) -> str:
        """Cache a session's events (bounded) and, optionally, its deduped rule
        findings so downstream endpoints (hypotheses) don't re-run
        ``ThreatRuleEngine.evaluate_all`` on the same data.

        If ``session_id`` is given it is reused (overwrite); otherwise a new
        unguessable id is minted.
        """
        bounded = _strip_raw(list(events)[: self.max_events])
        stored_findings = list(findings) if findings else None
        with self._lock:
            self._evict_expired()
            sid = session_id or ("sess_" + secrets.token_hex(16))
            now = self._now()
            self._store[sid] = {
                "events": bounded,
                "findings": stored_findings,
                "created": now,
                "accessed": now,
            }
            # LRU eviction when over the session cap.
            while len(self._store) > self.max_sessions:
                oldest = min(self._store.items(), key=lambda kv: kv[1]["accessed"])[0]
                if oldest == sid:  # never evict the one we just inserted
                    break
                self._store.pop(oldest, None)
            return sid

    def get(self, session_id: str) -> Optional[List[dict]]:
        """Return a copy of the session's events, refreshing its access time.

        Returns a shallow copy of the list so callers can freely mutate their
        own view without polluting the cache (the previous behaviour handed
        out the internal list by reference).
        """
        with self._lock:
            self._evict_expired()
            rec = self._store.get(session_id)
            if rec is None:
                return None
            rec["accessed"] = self._now()
            return list(rec["events"])

    def get_findings(self, session_id: str) -> Optional[List[dict]]:
        """Return the cached deduped findings, or None if the session has none."""
        with self._lock:
            self._evict_expired()
            rec = self._store.get(session_id)
            if rec is None:
                return None
            rec["accessed"] = self._now()
            stored = rec.get("findings")
            return list(stored) if stored is not None else None

    def exists(self, session_id: str) -> bool:
        return self.get(session_id) is not None

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._store)

    def _reset(self) -> None:  # test helper
        with self._lock:
            self._store = {}
