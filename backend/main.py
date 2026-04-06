"""BlueHound — Threat Hunting Platform API Server"""
import os, json, tempfile, shutil, logging, re, time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
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
MAX_FILE_BYTES          = 50 * 1024 * 1024   # 50 MB upload limit
MAX_EVENTS_SUMMARY      = 5_000              # /api/llm/summarize events cap
MAX_CMDLINE_LEN         = 32_768             # /api/llm/analyze commandline cap
ALLOWED_EXTENSIONS      = {".json", ".csv", ".xml", ".log"}
MITRE_ID_RE             = re.compile(r"^T\d{4}(\.\d{3})?$")
# VULN-24: safe filename sanitizer (strip newlines/control chars)
_SAFE_FILENAME_RE       = re.compile(r"[^\w.\-_ ]")

# VULN-07: restrict to localhost by default; override via env
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:8443,http://127.0.0.1:8443"
).split(",")

# VULN-01: API key authentication
API_KEY = os.getenv("BLUEHOUND_API_KEY", "")

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


def _check_api_key(request: Request) -> None:
    """Require X-API-Key header if BLUEHOUND_API_KEY is set in .env."""
    if not API_KEY:
        return  # dev mode: no key configured → open (local-only)
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        logger.warning("Rejected request from %s — invalid API key", request.client.host)
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def _allowlist_ctx(ctx: dict) -> dict:
    """VULN-23: Strip unknown keys from event_context to prevent context poisoning."""
    if not isinstance(ctx, dict):
        return {}
    sanitized = {k: v for k, v in ctx.items() if k in ALLOWED_CTX_FIELDS}
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


# ── Security Headers Middleware ───────────────────────────────
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
            "script-src 'self' https://d3js.org https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "  # TODO: replace with nonce
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://d3js.org; "
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
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

# VULN-04: restricted CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    allow_credentials=False,
)
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


# ── API Endpoints ─────────────────────────────────────────────

@app.post("/api/upload")
@limiter.limit("20/minute")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    _auth: Any = Depends(_check_api_key),
):
    """Upload and ingest a log file (JSON/CSV/XML/LOG). Max 50 MB."""
    t0 = time.monotonic()

    # Validate extension
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported format. Allowed: {sorted(ALLOWED_EXTENSIONS)}")

    # VULN-03: enforce file size limit
    content = await file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds maximum size of {MAX_FILE_BYTES // 1024 // 1024} MB")

    # VULN-24: sanitize filename before logging
    safe_name = _sanitize_filename(file.filename or "")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        tmp.write(content)
        tmp.close()
        events   = ingester.parse_file(tmp.name, suffix)
        findings = rule_engine.evaluate_all(events)
        graph_data = graph_engine.build_graph(events, findings)
        facets   = ingester.extract_facets(events)
        logger.info(
            "upload | file=%r suffix=%s events=%d findings=%d elapsed=%.2fs client=%s",
            safe_name, suffix, len(events), len(findings),
            time.monotonic() - t0, request.client.host,
        )
        return {
            "status": "ok", "event_count": len(events), "finding_count": len(findings),
            "graph": graph_data, "events": _strip_raw(events),
            "findings": findings, "facets": facets,
        }
    finally:
        os.unlink(tmp.name)


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
    events   = ingester.parse_file(str(sample_path), ".json")
    findings = rule_engine.evaluate_all(events)
    graph_data = graph_engine.build_graph(events, findings)
    facets = ingester.extract_facets(events)
    logger.info("sample | dataset=%s events=%d findings=%d client=%s",
                dataset, len(events), len(findings), request.client.host)
    return {
        "status": "ok", "dataset": dataset,
        "event_count": len(events), "finding_count": len(findings),
        "graph": graph_data, "events": _strip_raw(events),
        "findings": findings, "facets": facets,
    }


@app.post("/api/query/build")
@limiter.limit("60/minute")
async def build_query(
    request: Request,
    payload: dict,
    _auth: Any = Depends(_check_api_key),
):
    """Generate KQL/SPL/Sigma from structured filter."""
    fmt     = payload.get("format", "kql")
    filters = payload.get("filters", {})
    if fmt not in ("kql", "spl", "sigma"):
        raise HTTPException(400, "format must be one of: kql, spl, sigma")
    if not isinstance(filters, dict):
        raise HTTPException(400, "filters must be a JSON object")
    return {"query": query_builder.generate(filters, fmt)}


@app.post("/api/llm/analyze")
@limiter.limit("10/minute")   # VULN-20: strict LLM rate limit
async def analyze_cmdline(
    request: Request,
    payload: dict,
    _auth: Any = Depends(_check_api_key),
):
    """Analyze a CommandLine + event context for malicious intent."""
    cmdline = payload.get("commandline", "")
    if not cmdline or not isinstance(cmdline, str):
        raise HTTPException(400, "commandline is required and must be a string")
    # VULN-03: cap input length
    if len(cmdline) > MAX_CMDLINE_LEN:
        raise HTTPException(413, f"commandline exceeds {MAX_CMDLINE_LEN} character limit")
    ctx = payload.get("event_context", {})
    # VULN-23: allowlist context fields to prevent context poisoning
    ctx = _allowlist_ctx(ctx)
    logger.info("llm/analyze | len=%d client=%s", len(cmdline), request.client.host)
    result = await llm_analyzer.analyze(cmdline, event_context=ctx)
    return result


@app.post("/api/llm/summarize")
@limiter.limit("5/minute")   # VULN-20: very strict — expensive operation
async def summarize_session(
    request: Request,
    payload: dict,
    _auth: Any = Depends(_check_api_key),
):
    """Summarize log session findings."""
    events   = payload.get("events",   [])
    findings = payload.get("findings", [])
    if not isinstance(events, list) or not isinstance(findings, list):
        raise HTTPException(400, "events and findings must be arrays")
    if len(events) > MAX_EVENTS_SUMMARY:
        events = events[:MAX_EVENTS_SUMMARY]
    if len(findings) > 1000:
        findings = findings[:1000]
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


@app.get("/")
async def root():
    return FileResponse(str(FRONTEND / "index.html"))


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("BLUEHOUND_HOST", "127.0.0.1")
    port = int(os.getenv("BLUEHOUND_PORT", "8443"))
    uvicorn.run("main:app", host=host, port=port, reload=True,
                reload_includes=["*.yaml", "*.yml"])
