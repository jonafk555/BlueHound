#!/bin/bash
# BlueHound — One-command secure launcher
set -e

cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════╗"
echo "║       🔵 BlueHound Threat Hunter          ║"
echo "╚═══════════════════════════════════════════╝"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 required. Install from https://python.org"
    exit 1
fi

# Create venv if needed
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
echo "📦 Installing dependencies..."
pip3 install -q -r requirements.txt

# VULN-14: Run dependency vulnerability audit
echo "🔍 Running dependency security audit..."
pip-audit --desc on 2>&1 | grep -Ev "^No known|Found 0" || true

# Load .env for server config (BLUEHOUND_HOST, BLUEHOUND_PORT, etc.)
if [ -f ".env" ]; then
    set -o allexport
    source .env
    set +o allexport
else
    echo "⚠️  No .env found. Copy .env.example to .env and configure."
fi

# VULN-07: Default to localhost-only; override via .env
BLUEHOUND_HOST="${BLUEHOUND_HOST:-127.0.0.1}"
BLUEHOUND_PORT="${BLUEHOUND_PORT:-8443}"

echo ""
echo "🚀 Starting BlueHound on http://${BLUEHOUND_HOST}:${BLUEHOUND_PORT}"
echo "   Press Ctrl+C to stop"
echo ""
cd backend
python -m uvicorn main:app \
    --host "${BLUEHOUND_HOST}" \
    --port "${BLUEHOUND_PORT}" \
    --reload \
    --reload-include "*.yaml" \
    --reload-include "*.yml"
