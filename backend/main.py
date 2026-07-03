"""BlueHound — Threat Hunting Platform API Server"""
import asyncio
import base64, binascii, logging, os, re, secrets, tempfile, time
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, Literal

import anyio

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from ingest import LogIngester
from graph_engine import GraphEngine
from threat_rules import ThreatRuleEngine
from mitre_mapper import MitreMapper
from query_builder import QueryBuilder
from llm_analyzer import LLMAnalyzer
import triage as triage_mod
from triage import correlate_findings, validate_triage_update
from triage_store import TriageStore
from session_store import SessionStore, _strip_raw
from hunt_ir import HuntIRExecutor, ir_to_filters, validate_ir
from embeddings import SimilarityIndex
from pdf_report import build_session_report
from feedback_store import FeedbackStore
import model_governance as gov

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("bluehound")

# ── Constants ─────────────────────────────────────────────────
MAX_FILE_BYTES          = 200 * 1024 * 1024  # 200 MB upload limit
STREAM_CHUNK_SIZE       = 2 * 1024 * 1024    # 2 MB chunks for streaming upload to disk
MAX_EVENTS_SUMMARY      = 2_000              # /api/llm/summarize events cap
MAX_CMDLINE_LEN         = 32_768             # /api/llm/analyze commandline cap
MAX_HUNT_QUESTION_LEN   = 1_024              # /api/hunt/nl question cap (FR-1)
MAX_JSON_BODY_BYTES     = int(os.getenv("BLUEHOUND_MAX_JSON_BODY_BYTES", str(2 * 1024 * 1024)))
# Report POST body cap. PDF export takes the (already server-derived) dashboard
# state so the report reflects exactly what the analyst was looking at; we still
# hard-bound it so a client cannot POST an unbounded string blob back at us.
MAX_REPORT_BODY_BYTES   = int(os.getenv("BLUEHOUND_MAX_REPORT_BODY_BYTES", str(4 * 1024 * 1024)))
MAX_SUMMARY_FIELD_LEN   = 4_096
MAX_QUERY_FIELD_LEN     = 4_096
MAX_RESPONSE_EVENTS     = int(os.getenv("BLUEHOUND_MAX_RESPONSE_EVENTS", "10000"))
MAX_PARSED_EVENTS       = int(os.getenv("BLUEHOUND_MAX_PARSED_EVENTS", "50000"))
ALLOWED_EXTENSIONS      = {".json", ".csv", ".xml", ".log", ".evtx"}
MITRE_ID_RE             = re.compile(r"^T\d{4}(\.\d{3})?$")
# VULN-24: safe filename sanitizer (strip newlines/control chars)
_SAFE_FILENAME_RE       = re.compile(r"[^\w.\-_ ]")

# VULN-07: restrict to localhost by default; override via env
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:8443,http://127.0.0.1:8443"
).split(",")

# Authentication: production must fail closed if no key is configured.
#
# BLUEHOUND_API_KEY  → legacy single shared key. Anyone with it authenticates
#                      and may self-report any analyst name.
# BLUEHOUND_API_KEYS → per-analyst mapping "alice:key1,bob:key2". The analyst
#                      identity is SERVER-DERIVED from the key that authorized
#                      the request — clients cannot spoof `analyst` on
#                      /api/feedback or /api/llm/proposed-rules/*/approve. This
#                      is what makes the FR-5 poisoning defence (trust weights,
#                      trusted-analyst allowlist) actually load-bearing.
API_KEY = os.getenv("BLUEHOUND_API_KEY", "")
_API_KEYS_ENV = os.getenv("BLUEHOUND_API_KEYS", "").strip()


def _parse_analyst_keys(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, key = pair.split(":", 1)
        name, key = name.strip(), key.strip()
        if name and key:
            out[key] = name
    return out


ANALYST_KEYS: dict[str, str] = _parse_analyst_keys(_API_KEYS_ENV)  # key → analyst name
AUTH_REQUIRED = bool(API_KEY or ANALYST_KEYS)

APP_ENV = os.getenv("BLUEHOUND_ENV", "development").strip().lower()
CONFIGURED_HOST = os.getenv("BLUEHOUND_HOST", "127.0.0.1").strip()
# Startup auth gate removed by user request — the server now boots regardless
# of BLUEHOUND_API_KEY(S) / BLUEHOUND_ENV / bind interface. If a key is
# still configured, `_check_api_key` continues to enforce it at request time;
# with no key configured, every endpoint is open. Deploy behind a trusted
# perimeter or set a key if you need per-request auth.
if not AUTH_REQUIRED:
    logger.warning(
        "Startup auth gate disabled — no BLUEHOUND_API_KEY(S) configured. "
        "All /api endpoints accept unauthenticated requests. bind=%s env=%s",
        CONFIGURED_HOST, APP_ENV,
    )

# VULN-23: allowed event_context field names (allowlist)
ALLOWED_CTX_FIELDS = frozenset({
    "event_id", "EventID", "process_name", "hostname", "user_name",
    "matched_rules", "properties", "Properties", "object_guid",
})

# Rate limiter (per-IP).
#
# By default we key on the direct peer address — this is what slowapi does
# out-of-the-box and it is the correct choice when the process is exposed
# directly. When BlueHound is placed behind a *trusted* reverse proxy set
# BLUEHOUND_TRUST_XFF=1 to opt in to X-Forwarded-For parsing. NEVER enable
# this without a proxy that strips inbound XFF, otherwise attackers can
# forge a distinct value per request and bypass the limiter entirely.
_TRUST_XFF = os.getenv("BLUEHOUND_TRUST_XFF", "false").lower() == "true"


def _rate_limit_key(request: Request) -> str:
    if _TRUST_XFF:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # Take the *left-most* address — the original client per the RFC.
            return xff.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)


def _sanitize_filename(name: str) -> str:
    """VULN-24: Remove log-injection and path-traversal chars from user-supplied filename."""
    name = (name or "")[:200]
    # Strip control chars (including newlines/CR) for log injection
    name = "".join(c for c in name if c >= " " and c != chr(0x7f))
    # Replace unsafe chars (keep only word chars, dot, dash, underscore, space)
    name = _SAFE_FILENAME_RE.sub("_", name)
    # Block path traversal: replace ..
    name = name.replace("..", "_")
    return name or "unnamed"


def _request_api_key(request: Request) -> str:
    """Read an API key from X-API-Key or HTTP Basic password."""
    key = request.headers.get("X-API-Key", "")
    if key:
        return key
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return ""
    try:
        decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
        _, password = decoded.split(":", 1)
        return password
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _check_api_key(request: Request) -> str | None:
    """Require authentication when a key is configured.

    Returns the analyst name associated with the presented key (from
    BLUEHOUND_API_KEYS), or ``None`` when the request is authenticated with
    the legacy shared BLUEHOUND_API_KEY (or when no auth is configured).
    Stashes the derived identity on ``request.state.analyst`` for downstream
    handlers that need it (feedback, rule approval).
    """
    if not AUTH_REQUIRED:
        request.state.analyst = None
        return None
    presented = _request_api_key(request)
    if not presented:
        logger.warning("Rejected request from %s — missing API key", request.client.host)
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="BlueHound", charset="UTF-8"'},
        )
    # Try per-analyst mapping first (server-derived identity).
    for key, analyst in ANALYST_KEYS.items():
        if secrets.compare_digest(presented, key):
            request.state.analyst = analyst
            return analyst
    # Fall back to legacy shared key. Identity is anonymous.
    if API_KEY and secrets.compare_digest(presented, API_KEY):
        request.state.analyst = None
        return None
    logger.warning("Rejected request from %s — invalid API key", request.client.host)
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="BlueHound", charset="UTF-8"'},
    )


def _authenticated_analyst(request: Request) -> str | None:
    """Read the server-derived analyst identity (set by ``_check_api_key``)."""
    return getattr(request.state, "analyst", None)


def _allowlist_ctx(ctx: dict) -> dict:
    """VULN-23: Strip unknown keys from event_context to prevent context poisoning."""
    if not isinstance(ctx, dict):
        return {}
    sanitized = {k: v for k, v in ctx.items() if k in ALLOWED_CTX_FIELDS}
    field_limits = {
        "event_id": 32,
        "EventID": 32,
        "process_name": 200,
        "hostname": 200,
        "user_name": 200,
        "properties": 8192,
        "Properties": 8192,
        "object_guid": 200,
    }
    for key, limit in field_limits.items():
        if key in sanitized and sanitized[key] is not None:
            sanitized[key] = str(sanitized[key])[:limit]
    # Validate matched_rules structure
    if "matched_rules" in sanitized:
        rules = sanitized["matched_rules"]
        if isinstance(rules, list):
            sanitized["matched_rules"] = [
                {"name": str(r.get("name", ""))[:200],
                 "severity": str(r.get("severity", "LOW"))[:10]}
                for r in rules if isinstance(r, dict)
            ][:50]
        else:
            del sanitized["matched_rules"]
    return sanitized


def _bounded_value(value: Any, depth: int = 0) -> Any:
    """Bound untrusted summary records before prompt construction or response generation."""
    if depth >= 4:
        return str(value)[:MAX_SUMMARY_FIELD_LEN]
    if isinstance(value, str):
        return value[:MAX_SUMMARY_FIELD_LEN]
    if isinstance(value, dict):
        return {
            str(k)[:128]: _bounded_value(v, depth + 1)
            for k, v in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_bounded_value(v, depth + 1) for v in value[:100]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_SUMMARY_FIELD_LEN]


class QueryFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    destination_ip: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    process_name: str | list[str] | None = None
    hostname: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    user_name: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    event_id: int | str | None = None
    commandline_contains: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    commandline_regex: str | None = Field(default=None, max_length=MAX_QUERY_FIELD_LEN)
    time_range: str | None = Field(default=None, max_length=16)
    table: str | None = Field(default=None, max_length=64)
    index: str | None = Field(default=None, max_length=64)


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["kql", "spl", "sigma"] = "kql"
    filters: QueryFilters = Field(default_factory=QueryFilters)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commandline: str = Field(min_length=1, max_length=MAX_CMDLINE_LEN)
    event_context: dict[str, Any] = Field(default_factory=dict)


class SummaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_EVENTS_SUMMARY)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)


class HuntNLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=MAX_HUNT_QUESTION_LEN)
    session_id: str = Field(min_length=1, max_length=64, pattern=r"^sess_[a-f0-9]{8,40}$")
    conversation_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_\-]{1,64}$")


class SimilarRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    commandline: str = Field(min_length=1, max_length=MAX_CMDLINE_LEN)
    k: int = Field(default=5, ge=1, le=20)


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    commandline: str = Field(min_length=1, max_length=MAX_CMDLINE_LEN)
    context: dict[str, Any] = Field(default_factory=dict)
    agree: bool = True
    corrected_is_malicious: bool | None = None
    corrected_severity: int | None = Field(default=None, ge=1, le=10)
    note: str = Field(default="", max_length=2000)
    analyst: str = Field(min_length=1, max_length=120)
    llm_verdict: dict[str, Any] | None = None


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=64, pattern=r"^sess_[a-f0-9]{8,40}$")


class ExecuteIRRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=64, pattern=r"^sess_[a-f0-9]{8,40}$")
    ir: dict[str, Any] = Field(default_factory=dict)
    conversation_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_\-]{1,64}$")


class ReportPDFRequest(BaseModel):
    """Payload for /api/report/pdf.

    We deliberately take a snapshot of the browser-side dashboard state — the
    frontend already shipped the same data down from the analysis endpoint, so
    we don't have to persist any of it or re-run correlation. Everything is
    length-capped inside pdf_report before it hits the PDF canvas.
    """
    model_config = ConfigDict(extra="ignore")
    session_id: str | None = Field(default=None, max_length=64)
    event_count: int | None = Field(default=None, ge=0, le=100_000_000)
    events_truncated: bool | None = None
    finding_count: int | None = Field(default=None, ge=0, le=1_000_000)
    finding_severity_counts: dict[str, int] | None = None
    incidents: list[dict[str, Any]] | None = Field(default=None, max_length=200)
    findings: list[dict[str, Any]] | None = Field(default=None, max_length=5_000)
    hypotheses: list[dict[str, Any]] | None = Field(default=None, max_length=50)
    llm_prescan: dict[str, Any] | None = None
    llm_summary: dict[str, Any] | None = None
    incident_count: int | None = Field(default=None, ge=0, le=1_000_000)


class TriageUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=64, pattern=r"^inc_[a-f0-9]{6,40}$")
    status: str | None = Field(default=None, max_length=32)
    priority: str | None = Field(default=None, max_length=8)
    note: str | None = Field(default=None, max_length=2000)
    analyst: str | None = Field(default=None, max_length=120)


class FindingExcludeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=64, pattern=r"^inc_[a-f0-9]{6,40}$")
    finding_key: str = Field(min_length=1, max_length=32, pattern=r"^f_[a-f0-9]{6,40}$")
    excluded: bool = True
    suggested_priority: str | None = Field(default=None, max_length=8)


# ── Security Headers Middleware ───────────────────────────────
class JSONBodyLimitMiddleware(BaseHTTPMiddleware):
    """Cap the size of JSON request bodies for /api/* endpoints.

    The previous implementation ``await request.body()``-ed first and *then*
    checked the length. With Transfer-Encoding: chunked (no Content-Length), a
    client could stream gigabytes into memory before the check fired. This
    version consumes the body chunk-by-chunk, aborts the moment the running
    total exceeds the cap, and only replays the bytes into the ASGI scope if
    the body is legitimately small.
    """

    async def dispatch(self, request: Request, call_next):
        content_type = request.headers.get("content-type", "").lower()
        if not (request.url.path.startswith("/api/") and "application/json" in content_type):
            return await call_next(request)

        # The PDF report endpoint receives the (already-computed) dashboard
        # state, which is a strict superset of a normal JSON body — allow a
        # larger ceiling for it alone.
        cap = MAX_REPORT_BODY_BYTES if request.url.path.startswith("/api/report/") else MAX_JSON_BODY_BYTES

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"error": "Invalid Content-Length"})
            if declared > cap:
                return JSONResponse(status_code=413, content={"error": "JSON request body too large"})

        # Stream and count. We intentionally do NOT call request.body() — that
        # would buffer the whole request before enforcement.
        chunks: list[bytes] = []
        total = 0
        more_body = True
        while more_body:
            message = await request.receive()
            if message["type"] != "http.request":
                # Client disconnected mid-body, etc.
                return JSONResponse(status_code=400, content={"error": "Malformed request body"})
            body_chunk = message.get("body", b"") or b""
            total += len(body_chunk)
            if total > cap:
                return JSONResponse(status_code=413, content={"error": "JSON request body too large"})
            chunks.append(body_chunk)
            more_body = message.get("more_body", False)

        # Replay the buffered body to downstream middleware / handlers. Safe now
        # that we've bounded ``total``.
        buffered = b"".join(chunks)
        replayed = {"consumed": False}

        async def _receive():
            if replayed["consumed"]:
                return {"type": "http.disconnect"}
            replayed["consumed"] = True
            return {"type": "http.request", "body": buffered, "more_body": False}

        request._receive = _receive  # type: ignore[attr-defined]
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
        # VULN-19: Removed unsafe-inline for style-src (use nonce or hash in production)
        # For now, allow inline styles only for this local-tool context with a clear comment
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        return response


app = FastAPI(title="BlueHound", version="1.0.0", docs_url=None, redoc_url=None)

# Wire rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# VULN-21: Generic error handler — never expose stack traces to client
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s %s: %r", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Suppress detail for 5xx, pass through 4xx detail (user-facing)
    if exc.status_code >= 500:
        return JSONResponse(status_code=exc.status_code, content={"error": "Server error"})
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [
        {
            "location": ".".join(str(part) for part in error.get("loc", [])),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()[:20]
    ]
    return JSONResponse(status_code=422, content={"error": "Invalid request", "fields": errors})

# VULN-04: restricted CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    allow_credentials=False,
)
app.add_middleware(JSONBodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Global singletons
ingester      = LogIngester()
graph_engine  = GraphEngine()
rule_engine   = ThreatRuleEngine(str(Path(__file__).parent.parent / "playbooks" / "windows_hunting.yaml"))
mitre_mapper  = MitreMapper()
query_builder = QueryBuilder()
llm_analyzer  = LLMAnalyzer()
triage_store  = TriageStore()
session_store = SessionStore()          # FR-1: bounded + TTL server-side event cache
ir_executor   = HuntIRExecutor()        # FR-1: deterministic IR executor
token_budget  = gov.TokenBudget()       # CR-5: per-session token/cost budget
similarity_index = SimilarityIndex()    # FR-4: embedding similarity layer
feedback_store = FeedbackStore()        # FR-5: analyst verdict-level feedback

# FR-1.5: bounded conversational memory — the last IR's result indices, scoped
# to (session_id, conversation_id) so a conversation cannot leak indices from
# one session into another (which would silently apply the old numbers to a
# different event list and either return wrong data or 500 on out-of-range).
_conv_prev: dict[tuple[str, str], list] = {}
_CONV_CAP = 64
_CONV_KEEP = 5000


def _conv_key(session_id: str, conv_id: str | None) -> tuple[str, str] | None:
    if not conv_id or not session_id:
        return None
    return (session_id, conv_id)


def _conv_remember(session_id: str, conv_id: str | None, result_idx: list) -> None:
    key = _conv_key(session_id, conv_id)
    if key is None:
        return
    _conv_prev[key] = list(result_idx)[:_CONV_KEEP]
    # FIFO eviction — dict preserves insertion order.
    while len(_conv_prev) > _CONV_CAP:
        _conv_prev.pop(next(iter(_conv_prev)), None)


def _conv_recall(session_id: str, conv_id: str | None, n_events: int) -> list | None:
    """Return the remembered result indices for this (session, conversation),
    filtered to indices still valid for the current event count. Returns
    ``None`` when there is nothing to recall."""
    key = _conv_key(session_id, conv_id)
    if key is None:
        return None
    idx = _conv_prev.get(key)
    if not idx:
        return None
    # Defensive bound check: never hand the executor an out-of-range index.
    return [i for i in idx if 0 <= i < n_events]

FRONTEND   = Path(__file__).parent.parent / "frontend"
SAMPLE_DIR = Path(__file__).parent / "sample_data"


def _compute_finding_severity_counts(findings: list) -> dict:
    """Count deduplicated findings per severity for the unified stats bar."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


async def _run_analysis_pipeline(events: list) -> dict:
    """Central pipeline: LLM pre-scan first, then rules, graph, and facets.

    The three heavy synchronous stages (evaluate_all, build_graph, extract_facets)
    run in a threadpool so an in-flight upload does not block healthz or any
    other event-loop request. gc.collect() was previously called here to "free
    memory" — but the events list is still referenced by the session cache, so
    the collect was a several-hundred-millisecond no-op. Removed.
    """
    event_count = len(events)
    # Prescan gets the *whole* sample the caller passed us; the frontend must
    # not see events_prescanned diverge from what actually ran. (The pipeline's
    # own choice of prescan sample size is the caller's decision.)
    prescan = await llm_analyzer.prescan_session(events)
    findings = await anyio.to_thread.run_sync(rule_engine.evaluate_all, events)
    graph_data = await anyio.to_thread.run_sync(graph_engine.build_graph, events, findings)
    facets = await anyio.to_thread.run_sync(ingester.extract_facets, events)

    # Unified severity counts come from deduped findings so stats-bar matches
    # what the Threat Hunt / Process Tree / Timeline panels actually surface.
    finding_severity = _compute_finding_severity_counts(findings)
    graph_data.setdefault("stats", {})
    graph_data["stats"]["finding_critical"] = finding_severity["critical"]
    graph_data["stats"]["finding_high"]     = finding_severity["high"]
    graph_data["stats"]["finding_medium"]   = finding_severity["medium"]
    graph_data["stats"]["finding_low"]      = finding_severity["low"]

    # Correlate findings into incidents (LLM/rules lead) and merge persisted
    # human-on-the-loop triage state by stable incident fingerprint.
    incidents = correlate_findings(findings)
    incidents = triage_store.merge_into_incidents(incidents)

    # Build response events (truncated) and strip _raw
    response_events = _strip_raw(events[:MAX_RESPONSE_EVENTS])
    events_truncated = event_count > len(response_events)

    # FR-1: cache the (raw-stripped) session server-side so the NL hunt executor
    # can re-evaluate a structured IR against it. Bounded + TTL in SessionStore.
    # We also stash the deduped findings on the session so /api/llm/hypotheses
    # doesn't re-run the rule engine on the same data.
    session_id = session_store.put(events, findings=findings)

    return {
        "session_id": session_id,
        "event_count": event_count,
        "events_truncated": events_truncated,
        "returned_event_count": len(response_events),
        "finding_count": len(findings),
        "finding_severity_counts": finding_severity,
        "incidents": incidents,
        "incident_count": len(incidents),
        "llm_prescan": prescan,
        "graph": graph_data,
        "events": response_events,
        "findings": findings,
        "facets": facets,
    }


# ── API Endpoints ─────────────────────────────────────────────

@app.post("/api/upload")
@limiter.limit("10/minute")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    _auth: Any = Depends(_check_api_key),
):
    """Upload and ingest a log file (JSON/CSV/XML/LOG/EVTX). Max 200 MB."""
    t0 = time.monotonic()

    # Validate extension
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported format. Allowed: {sorted(ALLOWED_EXTENSIONS)}")

    # VULN-24: sanitize filename before logging
    safe_name = _sanitize_filename(file.filename or "")

    # VULN-03: stream upload to disk in chunks to avoid holding 200 MB in memory
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    total_bytes = 0
    try:
        while True:
            chunk = await file.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(413, f"File exceeds maximum size of {MAX_FILE_BYTES // 1024 // 1024} MB")
            tmp.write(chunk)
        tmp.close()

        try:
            # Offload the (fully synchronous) parser off the event loop.
            events = await anyio.to_thread.run_sync(
                ingester.parse_file, tmp.name, suffix, MAX_PARSED_EVENTS,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except RuntimeError as exc:
            logger.error("Parser runtime error for suffix=%s: %r", suffix, exc)
            raise HTTPException(500, "Parser dependency is unavailable") from exc
        analysis = await _run_analysis_pipeline(events)
        logger.info(
            "upload | file=%r suffix=%s size=%.1fMB events=%d findings=%d elapsed=%.2fs client=%s",
            safe_name, suffix, total_bytes / 1024 / 1024, analysis["event_count"], analysis["finding_count"],
            time.monotonic() - t0, request.client.host,
        )
        return {
            "status": "ok",
            **analysis,
        }
    finally:
        try:
            os.unlink(tmp.name)
        except FileNotFoundError:
            pass  # already cleaned up on size exceeded


@app.get("/api/sample")
@limiter.limit("30/minute")
async def load_sample(
    request: Request,
    dataset: str = Query("enterprise", pattern="^(enterprise|redteam|chaos)$"),
    _auth: Any = Depends(_check_api_key),
):
    """Load built-in sample dataset."""
    files = {
        "enterprise": SAMPLE_DIR / "enterprise_mixed.json",
        "redteam":    SAMPLE_DIR / "sysmon_redteam.json",
        "chaos":      SAMPLE_DIR / "chaos_realworld.json",
    }
    sample_path = files.get(dataset, files["enterprise"])
    events = await anyio.to_thread.run_sync(
        ingester.parse_file, str(sample_path), ".json", MAX_PARSED_EVENTS,
    )
    analysis = await _run_analysis_pipeline(events)
    logger.info("sample | dataset=%s events=%d findings=%d client=%s",
                dataset, analysis["event_count"], analysis["finding_count"], request.client.host)
    return {
        "status": "ok", "dataset": dataset,
        **analysis,
    }


@app.post("/api/query/build")
@limiter.limit("60/minute")
async def build_query(
    request: Request,
    payload: QueryRequest,
    _auth: Any = Depends(_check_api_key),
):
    """Generate KQL/SPL/Sigma from structured filter."""
    filters = payload.filters.model_dump(exclude_none=True)
    if isinstance(filters.get("process_name"), list):
        names = filters["process_name"]
        if len(names) > 50 or any(not isinstance(n, str) or len(n) > MAX_QUERY_FIELD_LEN for n in names):
            raise HTTPException(422, "process_name list exceeds allowed limits")
    return {"query": query_builder.generate(filters, payload.format)}


@app.post("/api/llm/analyze")
@limiter.limit("10/minute")   # VULN-20: strict LLM rate limit
async def analyze_cmdline(
    request: Request,
    payload: AnalyzeRequest,
    _auth: Any = Depends(_check_api_key),
):
    """Analyze a CommandLine + event context for malicious intent."""
    cmdline = payload.commandline
    ctx = payload.event_context
    # VULN-23: allowlist context fields to prevent context poisoning
    ctx = _allowlist_ctx(ctx)
    # FR-5.3: retrieve top-K similar TRUSTED past corrections as few-shot examples
    # (FR-4 embeddings for relevance). Sanitized + labelled as data in the prompt.
    try:
        few_shot = await feedback_store.retrieve_fewshot(cmdline, similarity_index.provider.embed)
    except Exception as exc:
        logger.warning("few-shot retrieval failed: %r", exc)
        few_shot = []
    logger.info("llm/analyze | len=%d few_shot=%d client=%s", len(cmdline), len(few_shot), request.client.host)
    result = await llm_analyzer.analyze(cmdline, event_context=ctx, few_shot=few_shot)
    result["few_shot_used"] = len(few_shot)
    return result


@app.post("/api/llm/summarize")
@limiter.limit("5/minute")   # VULN-20: very strict — expensive operation
async def summarize_session(
    request: Request,
    payload: SummaryRequest,
    _auth: Any = Depends(_check_api_key),
):
    """Summarize log session findings."""
    events = [_bounded_value(ev) for ev in payload.events]
    findings = [_bounded_value(f) for f in payload.findings]
    logger.info("llm/summarize | events=%d findings=%d client=%s",
                len(events), len(findings), request.client.host)
    result = await llm_analyzer.summarize_session(events, findings)
    return result


@app.post("/api/hunt/nl")
@limiter.limit("10/minute")   # FR-1: NL hunt — model-backed, strict limit (CR-5)
async def hunt_nl(
    request: Request,
    payload: HuntNLRequest,
    _auth: Any = Depends(_check_api_key),
):
    """FR-1: translate a natural-language question to a Hunt Query IR, execute it
    deterministically against the cached session events, and also render the IR
    to KQL/SPL/Sigma for the analyst's SIEM. The model only produces the IR; the
    executor (whitelisted fields + operators, no eval) makes the final decision."""
    events = session_store.get(payload.session_id)
    if events is None:
        raise HTTPException(410, "Session expired or not found — re-upload the dataset.")

    # CR-5: coarse token budget per session.
    ok, reason = token_budget.check_request(gov.estimate_tokens(payload.question))
    if not ok:
        raise HTTPException(429, reason)
    charged, reason = token_budget.charge(payload.session_id, gov.estimate_tokens(payload.question))
    if not charged:
        raise HTTPException(429, reason)

    translation = await llm_analyzer.translate_nl_to_ir(payload.question)
    ir = translation["ir"]

    previous_idx = _conv_recall(payload.session_id, payload.conversation_id, len(events))
    execution = ir_executor.execute(ir, events, previous_idx=previous_idx)

    _conv_remember(payload.session_id, payload.conversation_id, execution["result_idx"])

    filters = ir_to_filters(ir)
    results = _strip_raw(execution["results"][:200])
    explanation = (
        f"{ir.get('description') or 'Hunt'} — matched {execution['result_count']} event(s)"
        + (f" across steps {execution['step_counts']}" if len(ir.get('steps', [])) > 1 else "")
        + "."
    )
    logger.info("hunt/nl | session=%s qlen=%d source=%s results=%d client=%s",
                payload.session_id, len(payload.question), translation["source"],
                execution["result_count"], request.client.host)
    return {
        "ir": ir,
        "kql": query_builder.generate(filters, "kql") if filters else "",
        "spl": query_builder.generate(filters, "spl") if filters else "",
        "sigma": query_builder.generate(filters, "sigma") if filters else "",
        "results": results,
        "result_count": execution["result_count"],
        "returned_result_count": len(results),
        "step_counts": execution["step_counts"],
        "explanation": explanation,
        "source": translation["source"],
        "model_id": translation["model_id"],
        "llm_skipped_reason": translation.get("llm_skipped_reason"),
        "ir_errors": translation.get("errors", []),
    }


@app.post("/api/hunt/execute")
@limiter.limit("30/minute")   # FR-2.2: deterministic IR execution (no model)
async def hunt_execute(
    request: Request,
    payload: ExecuteIRRequest,
    _auth: Any = Depends(_check_api_key),
):
    """FR-1.3/FR-2.2: execute a (re-validated) Hunt Query IR against a cached
    session. No model is involved — this is the deterministic one-click runner
    used by hypothesis cards and saved queries."""
    events = session_store.get(payload.session_id)
    if events is None:
        raise HTTPException(410, "Session expired or not found — re-upload the dataset.")
    ir, errors = validate_ir(payload.ir)
    if not ir:
        raise HTTPException(422, {"error": "Invalid IR", "ir_errors": errors[:20]})
    previous_idx = _conv_recall(payload.session_id, payload.conversation_id, len(events))
    execution = ir_executor.execute(ir, events, previous_idx=previous_idx)
    _conv_remember(payload.session_id, payload.conversation_id, execution["result_idx"])
    return {
        "ir": ir,
        "ir_errors": errors,
        "results": _strip_raw(execution["results"][:200]),
        "result_count": execution["result_count"],
        "returned_result_count": min(200, execution["result_count"]),
        "step_counts": execution["step_counts"],
    }


@app.post("/api/llm/hypotheses")
@limiter.limit("5/minute")   # FR-2: model-backed, expensive — strict (CR-5)
async def llm_hypotheses(
    request: Request,
    payload: SessionRequest,
    _auth: Any = Depends(_check_api_key),
):
    """FR-2: generate ranked, grounded, executable hunt hypotheses for a session.
    Each hypothesis carries a Hunt Query IR; we execute it here so the board shows
    immediate supporting-evidence counts. Hypotheses citing entities/techniques
    absent from the session are dropped (FR-2.4 anti-hallucination)."""
    events = session_store.get(payload.session_id)
    if events is None:
        raise HTTPException(410, "Session expired or not found — re-upload the dataset.")

    charged, reason = token_budget.charge(payload.session_id, 1500)
    if not charged:
        raise HTTPException(429, reason)

    prescan = await llm_analyzer.prescan_session(events)
    # Reuse the deterministic findings computed at upload time when they are
    # still cached — a full re-evaluation on a large session is expensive.
    findings = session_store.get_findings(payload.session_id)
    if findings is None:
        findings = await anyio.to_thread.run_sync(rule_engine.evaluate_all, events)
    result = await llm_analyzer.generate_hypotheses(prescan, findings)

    # FR-2.2: run each validation_query so the card shows evidence immediately.
    for hyp in result["hypotheses"]:
        try:
            ex = ir_executor.execute(hyp["validation_query"], events)
            hyp["evidence_count"] = ex["result_count"]
            hyp["evidence_sample"] = _strip_raw(ex["results"][:5])
        except Exception as exc:
            logger.warning("hypothesis validation execute failed: %r", exc)
            hyp["evidence_count"] = 0
            hyp["evidence_sample"] = []

    logger.info("llm/hypotheses | session=%s count=%d source=%s client=%s",
                payload.session_id, len(result["hypotheses"]), result["source"], request.client.host)
    return {
        "hypotheses": result["hypotheses"],
        "source": result["source"],
        "model_id": result["model_id"],
        "llm_skipped_reason": result.get("llm_skipped_reason"),
    }


@app.post("/api/llm/similar")
@limiter.limit("20/minute")   # FR-4: embedding similarity lookup
async def llm_similar(
    request: Request,
    payload: SimilarRequest,
    _auth: Any = Depends(_check_api_key),
):
    """FR-4: nearest-neighbour to the known-bad corpus + clustering + novelty.
    A NEW signal that augments rules (CR-1) — it never changes a deterministic
    verdict on its own. Local-first embeddings; the vector store holds only
    numbers/ids/labels, never raw text replayed into a prompt (CR-3)."""
    result = await similarity_index.analyze(payload.commandline, k=payload.k)
    logger.info("llm/similar | len=%d bad=%.3f similar=%s src=%s client=%s",
                len(payload.commandline), result["max_known_bad_score"],
                result["similar_to_known_bad"], result["source"], request.client.host)
    return result


@app.post("/api/feedback")
@limiter.limit("30/minute")
async def submit_feedback(
    request: Request,
    payload: FeedbackRequest,
    _auth: Any = Depends(_check_api_key),
):
    """FR-5.1: record an analyst's verdict-level feedback (agree/disagree +
    optional corrected is_malicious/severity). Persisted as an annotated dataset
    that extends the eval ground truth and feeds few-shot learning."""
    ctx = _allowlist_ctx(payload.context)
    # Server-derived identity wins over the client-supplied `analyst` field
    # whenever per-analyst keys are configured — otherwise the entire FR-5
    # trust model is decoration (any holder of the shared key could self-
    # attest as a trusted analyst and poison the few-shot corpus).
    server_analyst = _authenticated_analyst(request)
    effective_analyst = server_analyst or payload.analyst
    rec = await feedback_store.add(
        commandline=payload.commandline, context=ctx, agree=payload.agree,
        corrected_is_malicious=payload.corrected_is_malicious,
        corrected_severity=payload.corrected_severity,
        note=payload.note, analyst=effective_analyst, llm_verdict=payload.llm_verdict,
        # Pre-compute embedding so future few-shot retrieval is O(N) cosine.
        embed_fn=similarity_index.provider.embed,
    )
    logger.info("feedback | id=%s analyst=%s agree=%s trust=%.1f client=%s",
                rec["id"], payload.analyst, payload.agree, rec["trust"], request.client.host)
    return {"status": "ok", "finding_id": rec["id"], "trust": rec["trust"],
            "label_is_malicious": rec["label_is_malicious"]}


@app.get("/api/feedback/export")
@limiter.limit("10/minute")
async def export_feedback(
    request: Request,
    deidentify: bool = Query(default=False),
    _auth: Any = Depends(_check_api_key),
):
    """FR-5.2/5.4: export the annotated feedback dataset as JSONL for offline
    fine-tune / eval. `deidentify=true` drops analyst identity + host/user context."""
    jsonl = feedback_store.export_jsonl(deidentify=deidentify)
    logger.info("feedback/export | bytes=%d deidentify=%s client=%s",
                len(jsonl), deidentify, request.client.host)
    return PlainTextResponse(jsonl, media_type="application/x-ndjson",
                             headers={"Content-Disposition": "attachment; filename=bluehound_feedback.jsonl"})


@app.get("/api/triage")
@limiter.limit("60/minute")
async def list_triage(request: Request, _auth: Any = Depends(_check_api_key)):
    """Return all persisted human-on-the-loop triage decisions (keyed by incident id)."""
    return {"triage": triage_store.all()}


@app.post("/api/triage")
@limiter.limit("60/minute")
async def update_triage(
    request: Request,
    payload: TriageUpdate,
    _auth: Any = Depends(_check_api_key),
):
    """Apply an analyst triage decision to an incident: status (排除 / 已修正 /
    待修正 / 接受風險) and/or fix priority (P0–P3). Partial updates preserve
    unspecified fields. Persisted by stable incident fingerprint."""
    err = validate_triage_update(payload.status, payload.priority)
    if err:
        raise HTTPException(422, err)
    try:
        rec = triage_store.upsert(
            payload.incident_id,
            status=payload.status,
            priority=payload.priority,
            note=payload.note,
            analyst=payload.analyst,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    logger.info("triage | incident=%s status=%s priority=%s client=%s",
                payload.incident_id, payload.status, payload.priority, request.client.host)
    return {"status": "ok", "incident_id": payload.incident_id, "triage": rec}


@app.post("/api/triage/finding")
@limiter.limit("120/minute")
async def exclude_finding(
    request: Request,
    payload: FindingExcludeRequest,
    _auth: Any = Depends(_check_api_key),
):
    """Exclude (or re-include) a single event in an incident's attack chain —
    lets the threat hunter drop a false-positive event without dismissing the
    whole incident. The incident's active severity is recomputed on next load."""
    rec = triage_store.set_finding_excluded(
        payload.incident_id, payload.finding_key, payload.excluded,
        suggested_priority=payload.suggested_priority or "P3",
    )
    logger.info("triage/finding | incident=%s key=%s excluded=%s client=%s",
                payload.incident_id, payload.finding_key, payload.excluded, request.client.host)
    return {"status": "ok", "incident_id": payload.incident_id,
            "excluded_findings": rec["excluded_findings"]}


@app.post("/api/report/pdf")
@limiter.limit("10/minute")
async def export_report_pdf(
    request: Request,
    payload: ReportPDFRequest,
    _auth: Any = Depends(_check_api_key),
):
    """Render the current session dashboard as a designed PDF report.

    The client posts the (already-bounded) analysis snapshot back — this keeps
    the endpoint stateless and lets the report reflect analyst-side edits
    (excluded findings, hypothesis status). All strings run through the
    escape/clip pipeline in ``pdf_report`` before touching the canvas, so an
    attacker-controlled log field cannot break the report structure.
    """
    analysis = payload.model_dump(exclude_none=True)
    # Stamp identity and generation time server-side so the PDF is not spoofable
    # from the client body.
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    requested_by = _authenticated_analyst(request) or ""
    try:
        pdf_bytes = await anyio.to_thread.run_sync(
            partial(build_session_report, analysis,
                    generated_at=generated_at, requested_by=requested_by),
        )
    except Exception as exc:
        logger.exception("PDF generation failed: %r", exc)
        raise HTTPException(500, "Failed to render PDF report") from exc

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    filename = _sanitize_filename(f"bluehound-report-{stamp}.pdf")
    logger.info("report/pdf | events=%s findings=%s size=%d client=%s",
                analysis.get("event_count"), analysis.get("finding_count"),
                len(pdf_bytes), request.client.host)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.get("/api/rules")
@limiter.limit("30/minute")
async def get_rules(request: Request, _auth: Any = Depends(_check_api_key)):
    """Return loaded playbook rules summary."""
    return rule_engine.get_rules_summary()


@app.get("/api/mitre/{technique_id}")
@limiter.limit("60/minute")
async def get_mitre_info(
    request: Request,
    technique_id: str,
    _auth: Any = Depends(_check_api_key),
):
    """Lookup MITRE ATT&CK technique info."""
    if not MITRE_ID_RE.match(technique_id):
        raise HTTPException(400, "Invalid technique_id format. Expected e.g. T1059 or T1059.001")
    return mitre_mapper.lookup(technique_id)


# ── Static Frontend ───────────────────────────────────────────
app.mount("/css",    StaticFiles(directory=str(FRONTEND / "css")),    name="css")
app.mount("/js",     StaticFiles(directory=str(FRONTEND / "js")),     name="js")
app.mount("/assets", StaticFiles(directory=str(FRONTEND / "assets")), name="assets")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/")
async def root(_auth: Any = Depends(_check_api_key)):
    return FileResponse(str(FRONTEND / "index.html"))


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("BLUEHOUND_HOST", "127.0.0.1")
    port = int(os.getenv("BLUEHOUND_PORT", "8443"))
    uvicorn.run("main:app", host=host, port=port, reload=True,
                reload_includes=["*.yaml", "*.yml"])
