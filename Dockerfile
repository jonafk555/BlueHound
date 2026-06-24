# ── Stage 1: dependency builder ─────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps (for wheels that need compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ───────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="BlueHound" \
      org.opencontainers.image.description="Graph-driven Windows threat hunting workbench" \
      org.opencontainers.image.version="1.0.0"

# Security: run as non-root
RUN groupadd -r bluehound && useradd -r -g bluehound -d /app -s /sbin/nologin bluehound

WORKDIR /app

# Copy pre-installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source (ensure readable by non-root user regardless of host perms)
COPY --chmod=755 backend/   ./backend/
COPY --chmod=755 frontend/  ./frontend/
COPY --chmod=755 playbooks/ ./playbooks/

# Create writable tmp dir for uploads (used by tempfile in main.py)
RUN mkdir -p /tmp/bluehound && chown bluehound:bluehound /tmp/bluehound

# Drop to non-root for runtime
USER bluehound

# Expose service port
EXPOSE 8443

# Health check uses a non-sensitive endpoint and does not bypass API authentication.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/healthz')" || exit 1

# Default env (overrideable via docker run -e / compose env_file)
ENV BLUEHOUND_HOST=0.0.0.0 \
    BLUEHOUND_PORT=8443 \
    BLUEHOUND_ENV=production \
    LLM_BACKEND=fallback \
    OLLAMA_URL=http://ollama:11434 \
    OLLAMA_MODEL=llama3.2 \
    OPENAI_MODEL=gpt-4o-mini

WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--workers", "1", \
     "--log-level", "info"]
