# 🔵 BlueHound

### Graph-Driven Threat Hunting Workbench

[中文版](./README.md)

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.138-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v15-ED1C24?logo=data:image/svg+xml;base64,PHN2Zy8+&logoColor=white)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**BlueHound** is a graph-driven Windows / Linux threat hunting platform that integrates LLM semantic analysis, MITRE ATT&CK mapping, interactive process trees, and force-directed graph visualization. It helps blue team analysts quickly identify attack chains from large volumes of security logs.

[Features](#-features) · [Quick Start](#-quick-start) · [Architecture Overview](#-architecture-overview) · [API Reference](#-api-reference) · [Security Hardening](#-security-hardening)

---

## 📸 Preview

- `Graph View`: Enables threat hunters to quickly analyze relations among multiple `IPs`, `Hosts`, `Parent Processes`, and `Child Processes` through a force-directed graph.
<img width="1502" height="818" alt="image" src="https://github.com/user-attachments/assets/8b1a8438-3733-4ded-b0c1-144c49e7a7bd" />

- `Process Tree`: Helps threat hunters understand the relationships between different processes. Highlighting threat risks via LLM allows threat hunters to quickly identify the sources of risk.
<img width="1502" height="818" alt="image" src="https://github.com/user-attachments/assets/abc5785f-8971-4e28-a78b-27eacee5fb93" />

- `Timeline`: Threat hunters can filter by time ranges, threat levels, hosts, or processes to trace threats occurring across different timeframes.
<img width="1502" height="818" alt="image" src="https://github.com/user-attachments/assets/38937000-1565-4dd5-9f6b-5c94a53b8a3d" />

- `Threat Hunt`: Highlights potential risks directly, allowing threat hunters to grasp key threat indicators in the shortest time for further analysis.
<img width="1502" height="818" alt="image" src="https://github.com/user-attachments/assets/71e3de54-9eeb-4269-8aab-da03bc41fa94" />

- `LLM Analyzer`: Upon importing logs, the LLM automatically scans the logs for potential threats beforehand and highlights the overview in the Session Summary. Users can also query the LLM to learn more about specific threats.
<img width="1502" height="818" alt="image" src="https://github.com/user-attachments/assets/4e6e5e95-3aa2-4981-9fe8-8192d5981014" />


> Upload Windows / Linux security logs → Automatic Parsing → Rule Engine Detection → LLM Semantic Pre-scan → Graph Visualization → Generate Hunting Report

---

## ✨ Features

### 🔍 Multi-Format Log Parsing Engine
- **Supported Formats**: JSON, CSV (including Kibana exports), XML (Windows Event Log), LOG (NDJSON/Syslog), EVTX (Native Windows Event)
- **Large File Streaming Parser**: Automatically switches to streaming mode for files exceeding 50 MB, supporting three streaming strategies: NDJSON, concatenated JSON, and JSON Array.
- **Unified Normalization**: Automaps 60+ field aliases to a 6-dimensional standard schema (Meta/Process/Network/File/AD/Label).

### 🧠 LLM Semantic Analysis (Three-Tier Fallback Architecture)
| Tier | Engine | Description |
|------|------|------|
| 1 | **Ollama** (Local) | Privacy-first, zero risk of data leakage. |
| 2 | **OpenAI** (Cloud) | Cloud-based backup engine with high accuracy. |
| 3 | **Heuristic Engine** | 30+ regex rules for zero-latency offline analysis. |

- **Pre-Scan Pipeline**: Automatically performs semantic pre-scanning (Plan → Execute → Report) upon log upload.
- **Command Line Analysis**: Identifies obfuscated PowerShell, AMSI/ETW bypass, download cradles, and DCSync attacks.
- **Session Summary**: Generates high-level threat intelligence reports containing attack narratives, affected hosts/accounts, and recommended actions.

### 🛡️ Threat Detection Engine
- **24 YAML Playbook Rules** covering 14 MITRE ATT&CK techniques.
- **SSH Brute Force Correlation Detection**: Correlates events across timelines to identify three distinct stages: enumeration → target account identification → compromise.
- **DCSync Fast Detection**: Uses GUID comparison + EID 4662 dedicated execution paths.
- **Abnormal Parent-Child Process Detection**: Identifies anomalies based on known legitimate process relationships.

### 📊 Interactive Visualization
- **Force-Directed Graph** (D3.js): Visualizes process nodes + network nodes with threat-severity coloring.
- **Process Tree**: Hierarchical parent-child process relationship expansion.
- **Timeline**: Chronological event sequence analysis.
- **KQL / SPL / Sigma Query Generator**: One-click generation of hunting queries ready for Sentinel, Splunk, or other SIEMs.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- (Optional) [Ollama](https://ollama.ai) — For local LLM inference
- (Optional) Docker & Docker Compose

### Method 1: One-Click Startup (Recommended)

```bash
git clone https://github.com/jonafk555/BlueHound.git
cd BlueHound

# Copy environment template
cp .env.example .env
# Edit .env to configure LLM backend and API Key

# Start the application
chmod +x run.sh
./run.sh
```

Once started, open your browser and navigate to: **http://localhost:8443**

### Method 2: Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 --reload
```

### Method 3: Docker Compose

```bash
# Production mode
docker compose up -d

# Development mode (with hot-reload)
docker compose -f docker-compose.yml -f docker-compose.override.yml up
```

> **GPU Acceleration**: Uncomment the GPU configuration block under the Ollama service in `docker-compose.yml` to enable NVIDIA GPU support.

---

## 🏗️ Architecture Overview

```
BlueHound/
├── backend/                    # FastAPI Backend
│   ├── main.py                 # API server, routing, middlewares, and safety controls
│   ├── ingest.py               # Multi-format log parser and normalization engine
│   ├── graph_engine.py         # NetworkX graph engine (process tree + network topology)
│   ├── threat_rules.py         # YAML Playbook rules engine + SSH correlation detection
│   ├── llm_analyzer.py         # LLM semantic analysis (Ollama/OpenAI/Heuristic fallback)
│   ├── mitre_mapper.py         # MITRE ATT&CK offline mapping table
│   ├── query_builder.py        # KQL / SPL / Sigma query generator
│   └── sample_data/            # Pre-installed sample datasets
├── frontend/                   # Static Frontend
│   ├── index.html              # Single Page Application (SPA)
│   ├── css/main.css            # Styles (Dark Theme)
│   ├── js/
│   │   ├── app.js              # Core application logic
│   │   ├── graph.js            # D3.js force-directed graph
│   │   ├── timeline.js         # Timeline visualization
│   │   ├── process_tree.js     # Process tree visualization
│   │   ├── hunt_panel.js       # Hunting panel
│   │   ├── llm_panel.js        # LLM analysis panel
│   │   └── query_panel.js      # Query generator panel
│   └── assets/                 # Static assets
├── playbooks/
│   └── windows_hunting.yaml    # Threat hunting playbook (24 rules)
├── Dockerfile                  # Multi-stage build (builder + runtime)
├── docker-compose.yml          # Production deployment configuration (includes Ollama)
├── docker-compose.override.yml # Development override configurations
├── requirements.txt            # Python dependencies
├── run.sh                      # One-click startup script
└── .env.example                # Environment variables template
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
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
┌─────────┐  ┌──────────┐  ┌──────────┐
│ LLM Pre │  │  Rule    │  │  Graph   │
│  Scan   │  │  Engine  │  │  Engine  │
│(heuris.)│  │ (YAML)   │  │(NetworkX)│
└────┬────┘  └────┬─────┘  └────┬─────┘
     │            │             │
     └────────────┼─────────────┘
                  ▼
         ┌────────────────┐
         │  API Response  │  events + findings + graph + facets
         └────────┬───────┘
                  ▼
         ┌────────────────┐
         │   Frontend     │  D3.js Graph / Timeline / Hunt Panel
         └────────────────┘
```

---

## 📡 API Reference

All endpoints bind to `http://localhost:8443` by default. If `BLUEHOUND_API_KEY` is configured, you must include the `X-API-Key` header in requests.

### Log Upload & Analysis

| Method | Endpoint | Description | Rate Limit |
|--------|----------|------|------|
| `POST` | `/api/upload` | Upload log files (max 200MB) | 10/min |
| `GET` | `/api/sample?dataset=enterprise` | Load pre-installed sample dataset | 30/min |

**Supported Datasets**: `enterprise`, `redteam`, `chaos`

### LLM Analysis

| Method | Endpoint | Description | Rate Limit |
|--------|----------|------|------|
| `POST` | `/api/llm/analyze` | Semantic analysis for a single command line | 10/min |
| `POST` | `/api/llm/summarize` | Session-level threat summary | 5/min |

### Queries & Rules

| Method | Endpoint | Description | Rate Limit |
|--------|----------|------|------|
| `POST` | `/api/query/build` | Generate KQL / SPL / Sigma queries | 60/min |
| `GET` | `/api/rules` | List loaded Playbook rules | 30/min |
| `GET` | `/api/mitre/{technique_id}` | Query MITRE ATT&CK technique details | 60/min |

### Example: Upload and Analyze

```bash
curl -X POST http://localhost:8443/api/upload \
  -H "X-API-Key: YOUR_KEY" \
  -F "file=@/path/to/sysmon_logs.json"
```

### Example: Command Line Analysis

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

BlueHound enforces defense-in-depth principles right from the design phase, mapping against OWASP Top 10 guidelines:

### Implemented Safeguards

| ID | Category | Safeguards & Security Control |
|----|------|----------|
| VULN-01 | Authentication | API Key authentication (`BLUEHOUND_API_KEY`) |
| VULN-03 | Resource Management | Chunked file uploads (2MB chunks), max file size limit of 200MB, event parsing threshold at 150K events |
| VULN-04 | CORS | Restrictive CORS whitelist (never `*`) |
| VULN-06 | Injection | Escaped outputs for generated KQL/SPL/Sigma queries |
| VULN-07 | Network | Default binding to localhost (127.0.0.1) instead of 0.0.0.0 |
| VULN-10 | XXE | XML External Entity protection using `defusedxml` |
| VULN-14 | Supply Chain | Dependency vulnerability scanning with `pip-audit` |
| VULN-15 | LLM Security | Input sanitization and prompt injection detection |
| VULN-17 | SSRF | Whitelist validation for Ollama connection URL |
| VULN-19 | CSP | Robust Content-Security-Policy headers |
| VULN-20 | DoS | Per-IP rate limiting powered by slowapi |
| VULN-21 | Information Disclosure | Global generic error handler preventing traceback exposure |
| VULN-22 | Key Management | API Key read directly from environment variables on every request (no caching in memory) |
| VULN-23 | Context Injection | Strict whitelist constraints for LLM `event_context` fields |
| VULN-24 | Log Injection | Filename sanitization (filtering path traversals and control characters) |

### Docker Security

- **Non-root Execution**: Runs under the unprivileged `bluehound` user inside the container.
- **Read-Only Root Filesystem**: Enforced `read_only: true` with `tmpfs` mounts for temporary workspaces like /tmp.
- **Capabilities Dropping**: `cap_drop: ALL` drops all kernel capabilities.
- **Network Isolation**: Placed in an isolated bridge network `172.28.0.0/24`.
- **Security Headers**: Includes X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.

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

## ⚙️ Environment Configuration

All configurations are managed via a `.env` file or system environment variables. For a complete list of options, see [`.env.example`](.env.example).

| Variable | Default Value | Description |
|------|--------|------|
| `LLM_BACKEND` | `fallback` | LLM backend engine: `ollama` / `openai` / `fallback` |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama connection endpoint URL |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name |
| `OPENAI_API_KEY` | *(Empty)* | OpenAI API secret key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model name |
| `BLUEHOUND_HOST` | `127.0.0.1` | Backend binding address |
| `BLUEHOUND_PORT` | `8443` | Backend server port |
| `BLUEHOUND_API_KEY` | *(Empty)* | API key (leave blank to run in dev mode with no auth) |
| `ALLOWED_ORIGINS` | `http://localhost:8443,...` | Allowed CORS origins |
| `BLUEHOUND_MAX_PARSED_EVENTS` | `150000` | Maximum parsed events allowed |
| `BLUEHOUND_MAX_RESPONSE_EVENTS` | `50000` | Maximum response events allowed |

### Generating a Secure API Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📝 Custom Playbook Rules

Threat detection rules are defined in [`playbooks/windows_hunting.yaml`](playbooks/windows_hunting.yaml) using the following format:

```yaml
rules:
  - id: TH-025
    name: "Custom Rule Name"
    mitre: T1059.001
    tactic: Execution
    severity: HIGH          # CRITICAL / HIGH / MEDIUM / LOW
    match:
      process_name: ["powershell.exe"]
      commandline_regex: "(?i)(your-pattern-here)"
    description: "Describes what this custom rule detects."
    hunt_guidance: "Provides next steps/actions for threat analysts."
```

### Supported Match Criteria

| Parameter | Type | Description |
|------|------|------|
| `process_name` | string / list | Exact process name matching |
| `event_id` | int / list | Event ID matching |
| `commandline_regex` | string | Regular expression matching on the command line |
| `process_path_regex` | string | Regular expression matching on the process execution path |
| `properties_regex` | string | Regular expression matching on AD properties (EID 4662) |
| `event_outcome` | string / list | Event execution outcome (failed/success) |
| `action_type` | string / list | Event action type |
| `event_category` | string / list | Event category |
| `parent_child_anomaly` | bool | Abnormal parent-child process relationship detection |

---

## 🧰 Technology Stack

| Layer | Technologies |
|------|------|
| **Backend Framework** | FastAPI 0.138 + Uvicorn |
| **Graph Engine** | NetworkX |
| **Log Parsing** | json / csv / defusedxml / python-evtx |
| **LLM Integration** | httpx → Ollama API / OpenAI API |
| **Rate Limiting** | slowapi |
| **Frontend Rendering**| Vanilla JS + D3.js (Force-directed Graph / Timeline) |
| **Containerization** | Docker multi-stage + Compose |
| **Security Audit** | pip-audit |

---

## 🛠️ Development

### Local Development

```bash
# Install development dependencies
pip install -r requirements.txt

# Start backend with hot reload enabled
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 \
  --reload --reload-include "*.yaml" --reload-include "*.yml"
```

### Dependency Vulnerability Audit

```bash
pip-audit --desc on
```

### Docker Development Mode

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml up --build
```

Dev mode details:
- Source code is mounted as a volume supporting hot-reload.
- API Key verification is disabled.
- Read-only root filesystem restriction is disabled.

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">

**Built for Blue Teamers, by Blue Teamers** 🛡️

</div>
