"""Process-wide singleton ``httpx.AsyncClient``.

The previous code opened a new ``httpx.AsyncClient()`` in every LLM/embedding
call, which pays the TCP + TLS handshake cost on every request and eats FD
budget under load. Reuse a module-level client with sane connection pool
limits instead. Timeouts are still overridable per call.
"""
from __future__ import annotations

import atexit
import os
import threading

import httpx

_DEFAULT_TIMEOUT = float(os.getenv("BLUEHOUND_HTTP_TIMEOUT_S", "60"))
_MAX_CONNECTIONS = int(os.getenv("BLUEHOUND_HTTP_MAX_CONNECTIONS", "32"))
_MAX_KEEPALIVE = int(os.getenv("BLUEHOUND_HTTP_MAX_KEEPALIVE", "16"))

_lock = threading.Lock()
_client: httpx.AsyncClient | None = None


def get_async_client() -> httpx.AsyncClient:
    """Return the process-wide async HTTP client, creating it on first use."""
    global _client
    if _client is not None:
        return _client
    with _lock:
        if _client is None:
            _client = httpx.AsyncClient(
                timeout=_DEFAULT_TIMEOUT,
                limits=httpx.Limits(
                    max_connections=_MAX_CONNECTIONS,
                    max_keepalive_connections=_MAX_KEEPALIVE,
                ),
            )
    return _client


async def aclose() -> None:
    global _client
    if _client is not None:
        client, _client = _client, None
        await client.aclose()


@atexit.register
def _sync_close() -> None:
    # Best-effort synchronous cleanup on interpreter shutdown so we don't leak
    # sockets when uvicorn is killed without lifespan events firing.
    global _client
    if _client is not None:
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_client.aclose())
            loop.close()
        except Exception:
            pass
        _client = None
