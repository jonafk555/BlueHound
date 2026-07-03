"""FR-5: analyst verdict-level feedback store + few-shot retrieval.

Persists analyst corrections to LLM verdicts (agree/disagree, corrected
is_malicious / severity) as an annotated dataset. Two consumers:

  - FR-5.2 export: a JSONL ground-truth set for offline fine-tune / eval.
  - FR-5.3 few-shot: at analyze() time we retrieve the top-K most *similar*
    past corrections (via the FR-4 embedding provider) and inject them as
    labelled examples.

Security (feedback is both an injection surface and a poisoning surface):
  - Poisoning (OWASP LLM04): every record carries provenance (analyst) and a
    trust weight; few-shot draws ONLY from trusted analysts, and a command whose
    trusted labels disagree is treated as DISPUTED and excluded.
  - Injection (CR-3): retrieved example text is the caller's responsibility to
    sanitize + bound + label as data before it ever enters a prompt; this module
    returns plain {command, label} pairs and never builds prompts itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

_DIR = Path(os.getenv("BLUEHOUND_STATE_DIR", str(Path(tempfile.gettempdir()) / "bluehound")))
_DEFAULT_PATH = os.getenv("BLUEHOUND_FEEDBACK_DB", str(_DIR / "feedback.json"))
_MAX_RECORDS = 20_000
_MAX_CMD = 4096
_MAX_NOTE = 2000

# Trusted analysts (few-shot only learns from these). Comma-separated env list.
_TRUSTED = set(filter(None, (a.strip() for a in os.getenv("BLUEHOUND_TRUSTED_ANALYSTS", "").split(","))))
TRUST_TRUSTED = 1.0
TRUST_DEFAULT = 0.5
FEWSHOT_TRUST_MIN = float(os.getenv("BLUEHOUND_FEWSHOT_TRUST_MIN", "0.9"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def analyst_trust(analyst: str) -> float:
    return TRUST_TRUSTED if (analyst or "") in _TRUSTED else TRUST_DEFAULT


def _fingerprint(commandline: str, ctx: dict) -> str:
    rel = {k: (ctx or {}).get(k) for k in ("process_name", "event_id", "hostname")}
    blob = (commandline or "")[:_MAX_CMD] + "\x1f" + json.dumps(rel, sort_keys=True, default=str)
    return "fb_" + hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]


class FeedbackStore:
    def __init__(self, path: str = _DEFAULT_PATH):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._cache: Optional[List[Dict[str, Any]]] = None

    # ── persistence ────────────────────────────────────────────
    def _load(self) -> List[Dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, list):
                data = []
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            data = []
        self._cache = data
        return data

    def _flush(self, data: List[Dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        self._cache = data

    # ── public API ─────────────────────────────────────────────
    async def add(self, *, commandline: str, context: dict, agree: bool,
                  corrected_is_malicious: Optional[bool], corrected_severity: Optional[int],
                  note: str, analyst: str, llm_verdict: Optional[dict] = None,
                  embed_fn: Optional[Callable[[str], Awaitable[Any]]] = None) -> Dict[str, Any]:
        commandline = str(commandline or "")[:_MAX_CMD]
        fid = _fingerprint(commandline, context)
        # Ground-truth label: explicit correction wins; else agree => trust the LLM verdict.
        label_mal = corrected_is_malicious
        if label_mal is None and llm_verdict is not None:
            v = bool(llm_verdict.get("is_malicious"))
            label_mal = v if agree else (not v)
        # Pre-compute the embedding for retrieval-time reuse. Previously
        # retrieve_fewshot embedded every stored record on every analyze call —
        # once feedback grew past a few hundred rows and blew the embed cache,
        # each analyze made thousands of Ollama round-trips. Storing the vector
        # at write time turns few-shot into a single embed + N cosine sums.
        vec = None
        embed_source = None
        if embed_fn is not None:
            try:
                vec, embed_source = await embed_fn(commandline)
            except Exception:
                vec = None
        rec = {
            "id": fid,
            "commandline": commandline,
            "context": {k: str(context.get(k))[:200] for k in ("process_name", "event_id", "hostname", "user_name")
                        if isinstance(context, dict) and context.get(k) is not None},
            "agree": bool(agree),
            "corrected_is_malicious": (None if corrected_is_malicious is None else bool(corrected_is_malicious)),
            "corrected_severity": (None if corrected_severity is None else max(1, min(int(corrected_severity), 10))),
            "label_is_malicious": (None if label_mal is None else bool(label_mal)),
            "note": str(note or "")[:_MAX_NOTE],
            "analyst": str(analyst or "")[:120],
            "trust": analyst_trust(analyst),
            "created_at": _now_iso(),
            # Vector is optional; retrieval falls back to embedding on demand.
            "embedding": vec,
            "embedding_source": embed_source,
        }
        with self._lock:
            data = self._load()
            if len(data) >= _MAX_RECORDS:
                data = data[-(_MAX_RECORDS - 1):]
            data.append(rec)
            self._flush(data)
        return dict(rec)

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._load()]

    def export_jsonl(self, deidentify: bool = False) -> str:
        """FR-5.2/5.4: JSONL annotated dataset for offline fine-tune / eval.
        With deidentify=True, analyst identity and host/user context are dropped."""
        lines = []
        with self._lock:
            for r in self._load():
                row = {
                    "commandline": r["commandline"],
                    "label_is_malicious": r.get("label_is_malicious"),
                    "corrected_severity": r.get("corrected_severity"),
                }
                if not deidentify:
                    row["analyst"] = r.get("analyst", "")
                    row["context"] = r.get("context", {})
                    row["trust"] = r.get("trust", 0.5)
                lines.append(json.dumps(row, ensure_ascii=False))
        return "\n".join(lines)

    def _disputed_fingerprints(self, trust_min: float) -> set:
        """Fingerprints whose TRUSTED labels disagree → excluded from few-shot."""
        labels: Dict[str, set] = {}
        for r in self._load():
            if r.get("trust", 0) < trust_min or r.get("label_is_malicious") is None:
                continue
            labels.setdefault(r["id"], set()).add(bool(r["label_is_malicious"]))
        return {fid for fid, s in labels.items() if len(s) > 1}

    async def retrieve_fewshot(self, commandline: str,
                               embed_fn: Callable[[str], Awaitable[Any]],
                               k: int = 3, trust_min: float = FEWSHOT_TRUST_MIN,
                               min_similarity: float = 0.45) -> List[Dict[str, Any]]:
        """FR-5.3: top-K most similar TRUSTED, non-disputed past corrections.

        `embed_fn(text) -> (vector, source)` is the FR-4 provider. Returns
        [{command, label, severity, score}] — raw pairs; the caller sanitizes
        and labels them as data before any prompt use (CR-3).
        """
        from embeddings import _cosine
        with self._lock:
            records = [dict(r) for r in self._load()]
        disputed = self._disputed_fingerprints(trust_min)
        cands = [r for r in records
                 if r.get("trust", 0) >= trust_min
                 and r.get("label_is_malicious") is not None
                 and r["id"] not in disputed]
        if not cands:
            return []
        qvec, _ = await embed_fn(commandline)
        # Prefer the vector stored at write time — a cold retrieval used to
        # embed every single candidate on the hot path (see FeedbackStore.add).
        scored = []
        for r in cands:
            vec = r.get("embedding")
            if not vec:
                try:
                    vec, _ = await embed_fn(r["commandline"])
                except Exception:
                    continue
            s = _cosine(qvec, vec)
            if s >= min_similarity:
                scored.append((s, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        out = []
        seen = set()
        for s, r in scored:
            if r["id"] in seen:
                continue
            seen.add(r["id"])
            out.append({"command": r["commandline"],
                        "label": "malicious" if r["label_is_malicious"] else "benign",
                        "severity": r.get("corrected_severity"),
                        "score": round(s, 4)})
            if len(out) >= k:
                break
        return out

    def _reset(self) -> None:  # test helper
        with self._lock:
            self._cache = []
            try:
                if self.path.exists():
                    self.path.unlink()
            except OSError:
                pass
