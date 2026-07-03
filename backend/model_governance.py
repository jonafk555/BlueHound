"""Model governance: provenance stamping + token/cost budgets (CR-5, CR-8).

Every LLM-touched response must record which model produced it and where the
verdict came from (`source`: llm / heuristic / llm-invalid / llm-skipped). This
maps to OWASP LLM03 (model/version provenance) and gives the deterministic gates
a clean place to attach observability.

It also enforces a coarse per-process token budget so a misbehaving model or a
flood of requests cannot run up unbounded cost. Budgets are advisory bounds, not
billing — local Ollama is ~free, but the same code path guards cloud fallback.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

# Source provenance values (CR-8). Keep stable — the frontend keys off these.
SOURCE_LLM = "llm"
SOURCE_HEURISTIC = "heuristic"
SOURCE_LLM_INVALID = "llm-invalid"
SOURCE_LLM_SKIPPED = "llm-skipped"

# Rough token budgets. Defaults are generous for local use; tighten via env.
MAX_TOKENS_PER_REQUEST = int(os.getenv("BLUEHOUND_MAX_TOKENS_PER_REQUEST", "8000"))
MAX_TOKENS_PER_SESSION = int(os.getenv("BLUEHOUND_MAX_TOKENS_PER_SESSION", "200000"))
SESSION_BUDGET_TTL = int(os.getenv("BLUEHOUND_SESSION_BUDGET_TTL", "3600"))


def model_id_for(backend: str, ollama_model: str, openai_model: str) -> str:
    """Stable, human-readable model id for provenance (e.g. 'ollama/gemma4:e4b')."""
    if backend == "ollama":
        return f"ollama/{ollama_model}"
    if backend == "openai":
        return f"openai/{openai_model}"
    if backend == "fallback":
        return f"fallback/{ollama_model}"
    return "heuristic/none"


def stamp(result: Dict[str, Any], *, model_id: str, source: Optional[str] = None) -> Dict[str, Any]:
    """Attach model_id (+ optional source override) provenance to a result dict."""
    if not isinstance(result, dict):
        return result
    result["model_id"] = model_id
    if source is not None:
        result["source"] = source
    result.setdefault("source", SOURCE_HEURISTIC)
    return result


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token). Good enough for budgeting."""
    return max(1, len(text or "") // 4)


class TokenBudget:
    """Coarse per-process + per-session token budget (CR-5)."""

    def __init__(self,
                 per_request: int = MAX_TOKENS_PER_REQUEST,
                 per_session: int = MAX_TOKENS_PER_SESSION,
                 ttl: int = SESSION_BUDGET_TTL):
        self.per_request = per_request
        self.per_session = per_session
        self.ttl = ttl
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, float]] = {}  # sid -> {"tokens", "ts"}

    def _evict(self, now: float) -> None:
        for sid in [s for s, r in self._sessions.items() if now - r["ts"] > self.ttl]:
            self._sessions.pop(sid, None)

    def check_request(self, estimated_tokens: int) -> tuple[bool, str]:
        """True if a single request's estimate is within the per-request cap."""
        if estimated_tokens > self.per_request:
            return False, f"request token estimate {estimated_tokens} exceeds cap {self.per_request}"
        return True, ""

    def charge(self, session_id: Optional[str], tokens: int) -> tuple[bool, str]:
        """Charge tokens to a session budget. Returns (allowed, reason)."""
        if not session_id:
            return True, ""
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            rec = self._sessions.setdefault(session_id, {"tokens": 0.0, "ts": now})
            if rec["tokens"] + tokens > self.per_session:
                return False, f"session token budget exhausted ({self.per_session})"
            rec["tokens"] += tokens
            rec["ts"] = now
            return True, ""

    def _reset(self) -> None:  # test helper
        with self._lock:
            self._sessions = {}
