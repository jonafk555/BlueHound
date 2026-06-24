"""BlueHound — Threat Hunting Platform API Server"""
import base64, binascii, gc, logging, os, re, secrets, tempfile, time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
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
MAX_JSON_BODY_BYTES     = int(os.getenv("BLUEHOUND_MAX_JSON_BODY_BYTES", str(2 * 1024 * 1024)))
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
API_KEY = os.getenv("BLUEHOUND_API_KEY", "")
APP_ENV = os.getenv("BLUEHOUND_ENV", "development").strip().lower()
CONFIGURED_HOST = os.getenv("BLUEHOUND_HOST", "127.0.0.1").strip()
ALLOW_UNAUTHENTICATED = os.getenv("ALLOW_UNAUTHENTICATED", "false").lower() == "true"
if APP_ENV in {"production", "prod"} and not API_KEY:
    raise RuntimeError("BLUEHOUND_API_KEY is required when BLUEHOUND_ENV=production")
if not API_KEY and CONFIGURED_HOST not in {"127.0.0.1", "localhost", "::1"} and not ALLOW_UNAUTHENTICATED:
    raise RuntimeError(
        "Refusing unauthenticated non-loopback bind. Set BLUEHOUND_API_KEY or explicitly set "
        "ALLOW_UNAUTHENTICATED=true for an isolated development environment."
    )

# VULN-23: allowed event_context field names (allowlist)
ALLOWED_CTX_FIELDS = frozenset({
    "event_id", "EventID", "process_name", "hostname", "user_name",
    "matched_rules", "properties", "Properties", "object_guid",
})

# VULN-20: Rate limiter (per-IP)
limiter = Limiter(key_func=get_remote_address)


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


def _check_api_key(request: Request) -> None:
    """Require authentication when BLUEHOUND_API_KEY is configured."""
    if not API_KEY:
        return
    key = _request_api_key(request)
    if not key or not secrets.compare_digest(key, API_KEY):
        logger.warning("Rejected request from %s — invalid API key", request.client.host)
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="BlueHound", charset="UTF-8"'},
        )


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


# ── Security Headers Middleware ───────────────────────────────
class JSONBodyLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_type = request.headers.get("content-type", "").lower()
        if request.url.path.startswith("/api/") and "application/json" in content_type:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > MAX_JSON_BODY_BYTES:
                        return JSONResponse(status_code=413, content={"error": "JSON request body too large"})
                except ValueError:
                    return JSONResponse(status_code=400, content={"error": "Invalid Content-Length"})
            body = await request.body()
            if len(body) > MAX_JSON_BODY_BYTES:
                return JSONResponse(status_code=413, content={"error": "JSON request body too large"})
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

FRONTEND   = Path(__file__).parent.parent / "frontend"
SAMPLE_DIR = Path(__file__).parent / "sample_data"


def _strip_raw(events: list) -> list:
    """Remove internal _raw field before sending to client."""
    return [{k: v for k, v in ev.items() if k != "_raw"} for ev in events]


async def _run_analysis_pipeline(events: list) -> dict:
    """Central pipeline: LLM pre-scan first, then rules, graph, and facets.
    Optimized for memory: releases large objects as soon as they are no longer needed.
    """
    event_count = len(events)
    prescan = await llm_analyzer.prescan_session(events[:200])  # prescan only needs a sample
    findings = rule_engine.evaluate_all(events)
    graph_data = graph_engine.build_graph(events, findings)
    facets = ingester.extract_facets(events)

    # Build response events (truncated) and strip _raw
    response_events = _strip_raw(events[:MAX_RESPONSE_EVENTS])
    events_truncated = event_count > len(response_events)

    # Release the full events list to free memory before JSON serialization
    del events
    gc.collect()

    return {
        "event_count": event_count,
        "events_truncated": events_truncated,
        "returned_event_count": len(response_events),
        "finding_count": len(findings),
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
            events = ingester.parse_file(tmp.name, suffix, max_events=MAX_PARSED_EVENTS)
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
    events = ingester.parse_file(str(sample_path), ".json", max_events=MAX_PARSED_EVENTS)
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
    logger.info("llm/analyze | len=%d client=%s", len(cmdline), request.client.host)
    result = await llm_analyzer.analyze(cmdline, event_context=ctx)
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
