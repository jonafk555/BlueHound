<div align="center">

# 🔵 BlueHound

### Graph-Driven Threat Hunting Workbench

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.138-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v15-ED1C24?logo=data:image/svg+xml;base64,PHN2Zy8+&logoColor=white)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[中文版](./README.md)

**BlueHound** is a graph-driven Windows / Linux threat hunting platform that integrates LLM semantic analysis, MITRE ATT&CK mapping, interactive process trees, and force-directed graph visualization. It helps blue team analysts quickly identify attack chains from large volumes of security logs. Features include natural-language hunt queries, AI hypothesis generation, incident triage, embedding similarity analysis, and PDF report export.

[Features](#-features) · [Quick Start](#-quick-start) · [Architecture Overview](#-architecture-overview) · [API Reference](#-api-reference) · [Security Hardening](#-security-hardening) · [Configuration](#️-configuration)

</div>

---

## 📸 Preview

> Upload Windows / Linux security logs → Auto-parse → Rule engine detection → LLM semantic pre-scan → Embedding similarity → Graph visualization → Incident triage → PDF hunting report

---

## ✨ Features

### 🔍 Multi-Format Log Parsing Engine
- **Supported formats**: JSON, CSV (including Kibana exports), XML (Windows Event Log), LOG (NDJSON/Syslog), EVTX (native Windows events)
- **Large file streaming**: Automatically switches to streaming mode for files over 50 MB; supports NDJSON, concatenated JSON, and JSON Array streaming strategies
- **Unified normalization**: 60+ field aliases automatically mapped to a six-dimension standard schema (Meta / Process / Network / File / AD / Label)

### 🧠 LLM Semantic Analysis (Three-Tier Fallback)

| Tier | Engine | Description |
|------|--------|-------------|
| 1 | **Ollama** (local) | Privacy-first, zero data leakage risk |
| 2 | **OpenAI** (cloud) | High-precision analysis fallback |
| 3 | **Heuristic engine** | 30+ regex rules, zero-latency offline analysis |

- **Pre-Scan Pipeline**: Automatic semantic pre-scan on upload (Plan → Execute → Report)
- **Command-line analysis**: Identifies obfuscated PowerShell, AMSI/ETW bypass, download cradles, DCSync
- **Session summary**: Generates high-level threat intelligence reports with attack narrative, affected hosts/accounts, and recommended actions
- **Structured output validation**: All LLM JSON outputs are type-, length-, and enum-validated via `llm_schema.py`

### 💬 Natural-Language Hunting (FR-1)
- **NL → Hunt Query IR**: Analysts ask questions in natural language; the LLM translates them into a structured intermediate representation (Hunt Query IR)
- **Deterministic executor**: Whitelisted fields + operators only, no `eval`; the IR is executed safely server-side
- **Conversational follow-ups**: Multi-turn conversations with `use_previous` to scope to prior results
- **SIEM query export**: Simultaneously generates KQL / SPL / Sigma queries for direct import into Sentinel / Splunk

### 🎯 AI Hypothesis Generation (FR-2)
- **Ranked hypothesis cards**: Automatically generates prioritized threat hypotheses from session data
- **Grounded validation**: Each hypothesis carries an executable Hunt Query IR with immediate evidence counts
- **Anti-hallucination**: Hypotheses referencing entities/techniques absent from the session are automatically filtered out

### 🔗 Embedding Similarity Analysis (FR-4)
- **Local-first embeddings**: Ollama embeddings (e.g., nomic-embed-text); cloud is opt-in only
- **Known-bad matching**: Nearest-neighbor analysis against a seeded known-bad corpus
- **Clustering labels**: Similar activities are automatically grouped for triage
- **Novelty detection**: Distance measurement from the benign baseline
- **Deterministic fallback**: Falls back to hashed char-n-gram embeddings when no model is available

### 📝 Analyst Feedback Loop (FR-5)
- **Verdict feedback**: Analysts can agree/disagree with LLM verdicts and provide corrected labels
- **Few-shot learning**: Feedback from trusted analysts is automatically injected as examples for subsequent analyses
- **Trust weights**: Configurable trusted analyst list to prevent training set poisoning (OWASP LLM04)
- **JSONL export**: Annotated datasets can be exported for offline fine-tuning/evaluation, with optional de-identification

### 🛡️ Threat Detection Engine
- **25 YAML Playbook rules** covering multiple MITRE ATT&CK techniques
- **SSH brute force correlation**: Cross-event correlation identifying enumeration → target account → compromise stages
- **DCSync fast detection**: GUID matching + EID 4662 dedicated path
- **Anomalous parent-child process detection**: Based on known legitimate relationship baselines
- **ReDoS protection**: `regex_safety.py` validates all user/LLM-generated regex patterns for safety

### 🚨 Incident Correlation & Triage
- **Automatic incident correlation**: Aggregates findings into incidents by severity, time window, host/account dimensions
- **Priority suggestions**: Severity → P0–P3 auto-mapping (LLM/rules suggest, humans decide)
- **Human-on-the-loop**: Analysts can mark incidents as excluded, remediated, pending fix, or risk accepted
- **Fine-grained exclusion**: Individual findings within an incident can be excluded without dismissing the entire incident
- **Persistence**: Triage state is persisted as JSON; survives container restarts

### 📊 Interactive Visualization
- **Force-directed graph** (D3.js): Process nodes + network nodes + threat severity coloring
- **Process tree**: Hierarchical parent-child relationship expansion
- **Timeline**: Event temporal analysis
- **KQL / SPL / Sigma query generator**: One-click generation of hunting queries for SIEM import

### 📄 PDF Report Export
- **Branded design report**: Blue gradient title, severity color chips, dark cover panel
- **Fully offline**: Uses ReportLab — no Chromium or web font downloads required
- **Safe rendering**: All untrusted log strings are escaped and truncated
- **Server-stamped identity**: Analyst identity and generation time in the PDF are server-issued and cannot be spoofed

### 📈 Model Governance
- **Provenance tracking**: Every LLM response is stamped with `model_id` (e.g., `ollama/llama3.2`) and `source` (llm / heuristic / llm-invalid / llm-skipped)
- **Token budgets**: Per-request / per-session token limits to prevent runaway costs
- **Session TTL**: Budgets reset on a time-windowed basis

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- (Optional) [Ollama](https://ollama.ai) — Local LLM inference
- (Optional) Docker & Docker Compose

### Option 1: One-Command Launch (Recommended)

```bash
git clone https://github.com/jonafk555/BlueHound.git
cd BlueHound

# Copy environment config
cp .env.example .env
# Edit .env to configure LLM backend and API key

# Launch
chmod +x run.sh
./run.sh
```

Once started, open your browser at: **http://localhost:8443**

### Option 2: Manual Launch

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 --reload
```

### Option 3: Docker Compose

```bash
# Production (heuristic engine only)
docker compose up -d

# With Ollama local LLM
docker compose --profile llm up -d
```

> **GPU acceleration**: Uncomment the GPU configuration for the Ollama service in `docker-compose.yml` to enable NVIDIA GPU support.

---

## 🏗️ Architecture Overview

```
BlueHound/
├── backend/                        # FastAPI backend
│   ├── main.py                     # API server, routes, middleware, security
│   ├── ingest.py                   # Multi-format log parsing & normalization engine
│   ├── graph_engine.py             # NetworkX graph engine (process tree + network topology)
│   ├── threat_rules.py             # YAML Playbook rule engine + SSH correlation detection
│   ├── llm_analyzer.py             # LLM semantic analysis (Ollama/OpenAI/heuristic fallback)
│   ├── llm_schema.py               # LLM JSON output structured validation (CR-2)
│   ├── hunt_ir.py                  # Hunt Query IR validation + deterministic executor (FR-1)
│   ├── embeddings.py               # Embedding similarity layer (FR-4, local-first)
│   ├── feedback_store.py           # Analyst feedback persistence + few-shot retrieval (FR-5)
│   ├── triage.py                   # Incident correlation + human-on-the-loop triage model
│   ├── triage_store.py             # Triage state persistence (JSON)
│   ├── session_store.py            # Bounded, TTL'd server-side event cache
│   ├── model_governance.py         # Model provenance tracking + token budgets (CR-5, CR-8)
│   ├── pdf_report.py               # PDF session report (ReportLab)
│   ├── regex_safety.py             # ReDoS protection + bounded regex execution
│   ├── mitre_mapper.py             # MITRE ATT&CK offline lookup table
│   ├── query_builder.py            # KQL / SPL / Sigma query generator
│   ├── http_client.py              # Shared httpx async client
│   ├── time_utils.py               # Timestamp parsing utilities
│   └── sample_data/                # Built-in sample datasets
├── frontend/                       # Static frontend (SPA)
│   ├── index.html                  # Single-page application
│   ├── css/main.css                # Styles (dark theme)
│   ├── js/
│   │   ├── app.js                  # Core application logic
│   │   ├── graph.js                # D3.js force-directed graph
│   │   ├── timeline.js             # Timeline visualization
│   │   ├── process_tree.js         # Process tree visualization
│   │   ├── hunt_panel.js           # Rule-based hunting panel
│   │   ├── llm_panel.js            # LLM analysis panel + feedback UI
│   │   ├── nlhunt_panel.js         # Natural-language hunt panel (FR-1)
│   │   ├── hypotheses_panel.js     # AI hypothesis generation panel (FR-2)
│   │   ├── incidents_panel.js      # Incident triage panel
│   │   ├── query_panel.js          # Query generator panel
│   │   └── utils.js                # Shared utility functions
│   └── assets/                     # Static resources (favicon, etc.)
├── playbooks/
│   └── windows_hunting.yaml        # Threat hunting playbook (25 rules)
├── Dockerfile                      # Multi-stage build (builder + runtime)
├── docker-compose.yml              # Production deployment (with Ollama profile)
├── requirements.txt                # Python dependencies
├── run.sh                          # One-command launch script
└── .env.example                    # Environment variable template
```

### Data Flow

```
            ┌──────────────┐
            │  Log Upload  │  JSON / CSV / XML / LOG / EVTX
            └──────┬───────┘
                   ▼
          ┌────────────────┐
          │  LogIngester   │  Parse → Normalize (60+ field aliases)
          └────────┬───────┘
                   ▼
     ┌─────────────┼──────────────────┐
     ▼             ▼                  ▼
┌─────────┐  ┌──────────┐  ┌───────────────┐
│ LLM Pre │  │  Rule    │  │  Graph Engine  │
│  Scan   │  │  Engine  │  │  (NetworkX)    │
│(3-tier) │  │ (YAML)   │  │               │
└────┬────┘  └────┬─────┘  └──────┬────────┘
     │            │               │
     └────────────┼───────────────┘
                  ▼
         ┌────────────────┐
         │  Correlation   │  Incident correlation + embedding similarity
         └────────┬───────┘
                  ▼
         ┌────────────────┐
         │  API Response  │  events + findings + incidents + graph
         └────────┬───────┘
                  ▼
         ┌────────────────┐
         │   Frontend     │  Graph / Timeline / Hunt / Hypotheses /
         │                │  Incidents / NL Hunt / PDF Export
         └────────────────┘
```

---

## 📡 API Reference

All endpoints are bound to `http://localhost:8443` by default.

### Authentication

- Set `BLUEHOUND_API_KEY`: API clients use the `X-API-Key` header.
- Set `BLUEHOUND_API_KEYS`: Supports per-analyst keys (`alice:key1,bob:key2`); identity is server-derived from the key and cannot be spoofed.
- Browsers display an HTTP Basic login dialog when accessing the homepage (username is arbitrary; password is the API key).
- `BLUEHOUND_ENV=production` without a configured key will refuse to start.

### Log Upload & Analysis

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/upload` | Upload log file (max 200 MB) | 10/min |
| `GET` | `/api/sample?dataset=enterprise` | Load built-in sample dataset | 30/min |

**Available datasets**: `enterprise`, `redteam`, `chaos`

### LLM Analysis

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/llm/analyze` | Single command-line semantic analysis | 10/min |
| `POST` | `/api/llm/summarize` | Session-level threat summary | 5/min |
| `POST` | `/api/llm/hypotheses` | AI hypothesis generation (FR-2) | 5/min |
| `POST` | `/api/llm/similar` | Embedding similarity lookup (FR-4) | 20/min |

### Natural-Language Hunting (FR-1)

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/hunt/nl` | NL → Hunt Query IR → deterministic execution | 10/min |
| `POST` | `/api/hunt/execute` | Execute Hunt Query IR directly (no model) | 30/min |

### Analyst Feedback (FR-5)

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/feedback` | Submit verdict feedback (agree/disagree + correction) | 30/min |
| `GET` | `/api/feedback/export` | Export JSONL annotated dataset | 10/min |

### Incident Triage

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `GET` | `/api/triage` | List all triage decisions | 60/min |
| `POST` | `/api/triage` | Update incident triage status / priority | 60/min |
| `POST` | `/api/triage/finding` | Exclude/restore individual findings in an incident | 120/min |

### Report Export

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/report/pdf` | Export PDF session report | 10/min |

### Queries & Rules

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/query/build` | Generate KQL / SPL / Sigma queries | 60/min |
| `GET` | `/api/rules` | List loaded playbook rules | 30/min |
| `GET` | `/api/mitre/{technique_id}` | MITRE ATT&CK technique lookup | 60/min |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/healthz` | Service health check (no auth required) |

### Example: Upload & Analyze

```bash
curl -X POST http://localhost:8443/api/upload \
  -H "X-API-Key: YOUR_KEY" \
  -F "file=@/path/to/sysmon_logs.json"
```

### Example: Natural-Language Hunt

```bash
curl -X POST http://localhost:8443/api/hunt/nl \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "session_id": "YOUR_SESSION_ID",
    "question": "Which accounts executed PowerShell encoded commands in the last hour?"
  }'
```

### Example: Command-Line Analysis

```bash
curl -X POST http://localhost:8443/api/llm/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "commandline": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
    "event_context": {
      "event_id": 1,
      "process_name": "powershell.exe",
      "hostname": "WORKSTATION-01"
    }
  }'
```

---

## 🔐 Security Hardening

BlueHound incorporates OWASP Top 10 and OWASP LLM Top 10 security guidelines from the design phase, implementing defense-in-depth:

### Implemented Protections

| ID | Category | Protection |
|----|----------|------------|
| VULN-01 | Authentication | API Key / HTTP Basic auth; per-analyst key support; production fails closed without key |
| VULN-03 | Resource Management | Streaming upload, JSON body/field limits, model output token cap |
| VULN-04 | CORS | Restrictive CORS allowlist (not `*`) |
| VULN-06 | Injection | KQL/SPL literal escaping, Sigma uses YAML serializer |
| VULN-07 | Network | Binds to localhost (127.0.0.1) by default, not 0.0.0.0 |
| VULN-10 | XXE | `defusedxml` for XML External Entity prevention |
| VULN-14 | Supply Chain | `pip-audit` dependency vulnerability scanning |
| VULN-15 | LLM Safety | Skips model on prompt injection detection, structured prompts, deterministic severity floor |
| VULN-17 | SSRF | Ollama URL allowlist validation |
| VULN-19 | CSP | Content-Security-Policy headers, self-hosted D3 |
| VULN-20 | DoS | Per-IP rate limiting (slowapi) |
| VULN-21 | Info Leak | Generic error handler, no stack trace exposure |
| VULN-22 | Key Management | API key read from env on every request, never cached in memory |
| VULN-23 | Context Injection | LLM event_context field allowlist |
| VULN-24 | Log Injection | Filename sanitization (strip control chars, path traversal) |

### LLM-Specific Security (OWASP LLM Top 10)

| Control | Protection |
|---------|------------|
| CR-1 | LLM is an auxiliary signal; deterministic rules lead; embedding similarity never overrides rule verdicts |
| CR-2 | All LLM outputs validated via `llm_schema.py`; Hunt Query IR uses whitelisted fields + operators |
| CR-3 | Vector store holds only numbers/IDs/labels — never replays raw log text into prompts |
| CR-5 | Per-request / per-session token budgets to prevent runaway costs |
| CR-8 | Every response stamped with `model_id` + `source` provenance |
| LLM04 | Few-shot draws only from trusted analysts; disputed labels are excluded (anti-poisoning) |

### ReDoS Protection

- `regex_safety.py` pre-validates all user-submitted / LLM-generated regex patterns
- Nested quantifier detection (catastrophic backtracking pattern rejection)
- Per-IR cumulative time budget (`BLUEHOUND_IR_REGEX_BUDGET_S`)
- Search text truncation limit (16,384 characters)

### Docker Security

- **Non-root execution**: Runs as `bluehound` user inside the container
- **Read-only root filesystem**: `read_only: true` + `tmpfs` for /tmp
- **Capability drop**: `cap_drop: ALL`
- **Isolated network**: Dedicated bridge network `172.28.0.0/24`
- **Security headers**: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Persistent volume**: Triage/feedback state persisted via `bluehound-state` volume

---

## 🗺️ MITRE ATT&CK Coverage

```
┌─────────────────────┬──────────────────────────────────────────────────┐
│ Tactic              │ Techniques                                      │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Execution           │ T1059.001  PowerShell                           │
│                     │ T1047      WMI                                  │
│                     │ T1204.002  Malicious File                       │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Defense Evasion     │ T1562.001  Disable/Modify Tools (AMSI)          │
│                     │ T1562.006  ETW Bypass                           │
│                     │ T1027      Obfuscation                          │
│                     │ T1218.005  MSHTA                                │
│                     │ T1218.010  Regsvr32                             │
│                     │ T1218.011  Rundll32                             │
│                     │ T1140      Certutil Decode                      │
│                     │ T1197      BITS Jobs                            │
│                     │ T1055      Process Injection                    │
│                     │ T1055.012  Process Hollowing                    │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Credential Access   │ T1003.001  LSASS Memory                        │
│                     │ T1003.006  DCSync                               │
│                     │ T1110.001  SSH Brute Force                      │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Persistence         │ T1053.005  Scheduled Task                       │
│                     │ T1547.001  Registry Run Keys                    │
│                     │ T1543.003  Windows Service                      │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Lateral Movement    │ T1021.002  SMB / PsExec                        │
│                     │ T1021.006  WinRM                                │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Privilege Escalation│ T1134.001  Token Impersonation                  │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Discovery           │ T1018      Remote System Discovery              │
│                     │ T1082      System Info Discovery                │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Command & Control   │ T1071.004  DNS over HTTPS                      │
└─────────────────────┴──────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

All settings are managed via `.env` file or environment variables. See [`.env.example`](.env.example) for the full list.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BACKEND` | `fallback` | LLM engine: `ollama` / `openai` / `fallback` |
| `ALLOW_CLOUD_FALLBACK` | `false` | Allow fallback to OpenAI when Ollama fails |
| `LLM_MAX_OUTPUT_TOKENS` | `1200` | Max model output tokens |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama service URL |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Ollama embedding model (FR-4) |
| `OPENAI_API_KEY` | *(empty)* | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model name |

### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `BLUEHOUND_HOST` | `127.0.0.1` | Server bind address |
| `BLUEHOUND_PORT` | `8443` | Server port |
| `BLUEHOUND_ENV` | `development` | `production` mode enforces API key |
| `BLUEHOUND_API_KEY` | *(empty)* | Shared API key; required in production |
| `BLUEHOUND_API_KEYS` | *(empty)* | Per-analyst keys (`alice:key1,bob:key2`) |
| `ALLOWED_ORIGINS` | `http://localhost:8443,...` | CORS allowed origins |

### Resource Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `BLUEHOUND_MAX_JSON_BODY_BYTES` | `2097152` | JSON API request body limit |
| `BLUEHOUND_MAX_PARSED_EVENTS` | `50000` | Max parsed events |
| `BLUEHOUND_MAX_RESPONSE_EVENTS` | `10000` | Max response events |
| `BLUEHOUND_MAX_TOKENS_PER_REQUEST` | `8000` | Per-request token limit |
| `BLUEHOUND_MAX_TOKENS_PER_SESSION` | `200000` | Per-session token limit |

### Persistence & Sessions

| Variable | Default | Description |
|----------|---------|-------------|
| `BLUEHOUND_STATE_DIR` | `/tmp/bluehound` | Persistent state directory |
| `BLUEHOUND_TRIAGE_DB` | `{STATE_DIR}/triage_state.json` | Triage state file path |
| `BLUEHOUND_FEEDBACK_DB` | `{STATE_DIR}/feedback.json` | Feedback database path |
| `BLUEHOUND_MAX_SESSIONS` | `8` | Max concurrent sessions |
| `BLUEHOUND_MAX_SESSION_EVENTS` | `50000` | Max cached events per session |
| `BLUEHOUND_SESSION_TTL` | `3600` | Session TTL (seconds) |

### Trust & Security

| Variable | Default | Description |
|----------|---------|-------------|
| `BLUEHOUND_TRUSTED_ANALYSTS` | *(empty)* | Trusted analyst list (comma-separated) |
| `BLUEHOUND_FEWSHOT_TRUST_MIN` | `0.9` | Minimum trust threshold for few-shot |
| `BLUEHOUND_IR_REGEX_BUDGET_S` | `0.25` | Per-IR regex cumulative time budget (seconds) |

### Generate a Secure API Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📝 Custom Playbook Rules

Threat detection rules are defined in [`playbooks/windows_hunting.yaml`](playbooks/windows_hunting.yaml) with the following format:

```yaml
rules:
  - id: TH-026
    name: "Custom Rule Name"
    mitre: T1059.001
    tactic: Execution
    severity: HIGH          # CRITICAL / HIGH / MEDIUM / LOW
    match:
      process_name: ["powershell.exe"]
      commandline_regex: "(?i)(your-pattern-here)"
    description: "Describe what this rule detects."
    hunt_guidance: "Provide next-step recommendations for the analyst."
```

### Supported Match Conditions

| Condition | Type | Description |
|-----------|------|-------------|
| `process_name` | string / list | Exact process name match |
| `event_id` | int / list | Event ID match |
| `commandline_regex` | string | Command-line regex match |
| `process_path_regex` | string | Process path regex match |
| `properties_regex` | string | AD properties regex match (EID 4662) |
| `event_outcome` | string / list | Event outcome (failed/success) |
| `action_type` | string / list | Action type |
| `event_category` | string / list | Event category |
| `parent_child_anomaly` | bool | Anomalous parent-child process relationship |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend Framework** | FastAPI 0.138 + Uvicorn |
| **Graph Engine** | NetworkX |
| **Log Parsing** | json / csv / defusedxml / python-evtx |
| **LLM Integration** | httpx → Ollama API / OpenAI API |
| **Embedding Models** | Ollama (nomic-embed-text) / OpenAI / hashed char-n-gram fallback |
| **PDF Reports** | ReportLab |
| **Rate Limiting** | slowapi |
| **Frontend** | Vanilla JS + D3.js (force-directed graph / timeline) |
| **Containerization** | Docker multi-stage + Compose (with Ollama profile) |
| **Security Audit** | pip-audit |

---

## 🛠️ Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Start (with hot reload)
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 \
  --reload --reload-include "*.yaml" --reload-include "*.yml"
```

### Dependency Security Audit

```bash
pip-audit --desc on
```

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">

**Built for Blue Teamers, by Blue Teamers** 🛡️

</div>
