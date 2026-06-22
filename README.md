<![CDATA[<div align="center">

# 🔵 BlueHound

### Graph-Driven Threat Hunting Workbench

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.138-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v15-ED1C24?logo=data:image/svg+xml;base64,PHN2Zy8+&logoColor=white)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**BlueHound** 是一個以圖學驅動的 Windows / Linux 威脅獵捕平台，整合 LLM 語意分析、MITRE ATT&CK 映射、互動式流程樹與力導向圖視覺化，幫助藍隊分析師快速從大量安全日誌中識別攻擊鏈。

[功能特色](#-功能特色) · [快速開始](#-快速開始) · [架構總覽](#-架構總覽) · [API 文件](#-api-reference) · [安全強化](#-安全強化)

</div>

---

## 📸 預覽

> 上傳 Windows / Linux 安全日誌 → 自動解析 → 規則引擎偵測 → LLM 語意預掃 → 圖學視覺化 → 產出獵捕報告

---

## ✨ 功能特色

### 🔍 多格式日誌解析引擎
- **支援格式**：JSON、CSV（含 Kibana 匯出）、XML（Windows Event Log）、LOG（NDJSON/Syslog）、EVTX（原生 Windows 事件）
- **大檔串流解析**：超過 50 MB 自動切換串流模式，支援 NDJSON、串接 JSON、JSON Array 三種串流策略
- **統一正規化**：60+ 欄位別名自動映射至六維度標準架構（Meta/Process/Network/File/AD/Label）

### 🧠 LLM 語意分析 (三層降級架構)
| 層級 | 引擎 | 說明 |
|------|------|------|
| 1 | **Ollama** (本地) | 隱私優先，無資料外洩風險 |
| 2 | **OpenAI** (雲端) | 高精度分析備援 |
| 3 | **啟發式引擎** | 30+ 正則規則，零延遲離線分析 |

- **Pre-Scan Pipeline**：上傳時自動執行語意預掃（Plan → Execute → Report）
- **命令列分析**：辨識混淆 PowerShell、AMSI/ETW Bypass、下載搖籃、DCSync
- **會話摘要**：生成高階威脅情報報告含攻擊敘事、受影響主機/帳號、行動建議

### 🛡️ 威脅偵測引擎
- **24 條 YAML Playbook 規則**，覆蓋 MITRE ATT&CK 14 個技術
- **SSH 暴力破解關聯偵測**：跨事件關聯，辨識列舉 → 目標帳號 → 攻陷三階段
- **DCSync 快速偵測**：GUID 比對 + EID 4662 專用路徑
- **異常父子流程偵測**：基於已知合法關係的異常檢測

### 📊 互動式視覺化
- **力導向圖** (D3.js)：流程節點 + 網路節點 + 威脅嚴重度色彩
- **流程樹**：階層式親子關係展開
- **時間線**：事件時序分析
- **KQL / SPL / Sigma 查詢產生器**：一鍵產出可匯入 Sentinel / Splunk / SIEM 的獵捕查詢

---

## 🚀 快速開始

### 前置需求
- Python 3.12+
- (選用) [Ollama](https://ollama.ai) — 本地 LLM 推理
- (選用) Docker & Docker Compose

### 方式一：一鍵啟動 (推薦)

```bash
git clone https://github.com/jonafk555/BlueHound.git
cd BlueHound

# 複製環境設定
cp .env.example .env
# 編輯 .env 設定 LLM 後端與 API Key

# 啟動
chmod +x run.sh
./run.sh
```

啟動完成後開啟瀏覽器：**http://localhost:8443**

### 方式二：手動啟動

```bash
# 建立虛擬環境
python3 -m venv venv
source venv/bin/activate

# 安裝依賴
pip install -r requirements.txt

# 啟動伺服器
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 --reload
```

### 方式三：Docker Compose

```bash
# 生產環境
docker compose up -d

# 開發環境 (含熱重載)
docker compose -f docker-compose.yml -f docker-compose.override.yml up
```

> **GPU 加速**：取消 `docker-compose.yml` 中 Ollama 服務的 GPU 設定註解即可啟用 NVIDIA GPU。

---

## 🏗️ 架構總覽

```
BlueHound/
├── backend/                    # FastAPI 後端
│   ├── main.py                 # API 伺服器、路由、中介軟體、安全機制
│   ├── ingest.py               # 多格式日誌解析與正規化引擎
│   ├── graph_engine.py         # NetworkX 圖學引擎 (流程樹 + 網路拓撲)
│   ├── threat_rules.py         # YAML Playbook 規則引擎 + SSH 關聯偵測
│   ├── llm_analyzer.py         # LLM 語意分析 (Ollama/OpenAI/啟發式三層降級)
│   ├── mitre_mapper.py         # MITRE ATT&CK 離線查詢表
│   ├── query_builder.py        # KQL / SPL / Sigma 查詢產生器
│   └── sample_data/            # 內建範例資料集
├── frontend/                   # 靜態前端
│   ├── index.html              # 單頁應用 (SPA)
│   ├── css/main.css            # 樣式 (暗色主題)
│   ├── js/
│   │   ├── app.js              # 核心應用邏輯
│   │   ├── graph.js            # D3.js 力導向圖
│   │   ├── timeline.js         # 時間線視覺化
│   │   ├── process_tree.js     # 流程樹視覺化
│   │   ├── hunt_panel.js       # 獵捕面板
│   │   ├── llm_panel.js        # LLM 分析面板
│   │   └── query_panel.js      # 查詢產生器面板
│   └── assets/                 # 靜態資源
├── playbooks/
│   └── windows_hunting.yaml    # 威脅獵捕 Playbook (24 條規則)
├── Dockerfile                  # 多階段建置 (builder + runtime)
├── docker-compose.yml          # 生產部署 (含 Ollama)
├── docker-compose.override.yml # 開發覆蓋設定
├── requirements.txt            # Python 依賴
├── run.sh                      # 一鍵啟動腳本
└── .env.example                # 環境變數範本
```

### 資料流

```
            ┌──────────────┐
            │  Log Upload  │  JSON / CSV / XML / LOG / EVTX
            └──────┬───────┘
                   ▼
          ┌────────────────┐
          │  LogIngester   │  解析 → 正規化 (60+ field aliases)
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

所有端點預設綁定 `http://localhost:8443`。如設定 `BLUEHOUND_API_KEY`，需在 Header 帶上 `X-API-Key`。

### 日誌上傳與分析

| Method | Endpoint | 說明 | 限速 |
|--------|----------|------|------|
| `POST` | `/api/upload` | 上傳日誌檔案 (max 200MB) | 10/min |
| `GET` | `/api/sample?dataset=enterprise` | 載入內建範例資料集 | 30/min |

**支援資料集**：`enterprise`、`redteam`、`chaos`

### LLM 分析

| Method | Endpoint | 說明 | 限速 |
|--------|----------|------|------|
| `POST` | `/api/llm/analyze` | 單一命令列語意分析 | 10/min |
| `POST` | `/api/llm/summarize` | 會話級威脅摘要 | 5/min |

### 查詢與規則

| Method | Endpoint | 說明 | 限速 |
|--------|----------|------|------|
| `POST` | `/api/query/build` | 產生 KQL/SPL/Sigma 查詢 | 60/min |
| `GET` | `/api/rules` | 列出已載入的 Playbook 規則 | 30/min |
| `GET` | `/api/mitre/{technique_id}` | MITRE ATT&CK 技術查詢 | 60/min |

### 範例：上傳分析

```bash
curl -X POST http://localhost:8443/api/upload \
  -H "X-API-Key: YOUR_KEY" \
  -F "file=@/path/to/sysmon_logs.json"
```

### 範例：命令列分析

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

## 🔐 安全強化

BlueHound 從設計階段即導入 OWASP Top 10 安全準則，實施多層防禦：

### 已實施防護措施

| ID | 類別 | 防護措施 |
|----|------|----------|
| VULN-01 | 認證 | API Key 驗證 (`BLUEHOUND_API_KEY`) |
| VULN-03 | 資源管理 | 串流上傳 (2MB chunks)、檔案大小上限 200MB、事件解析上限 150K |
| VULN-04 | CORS | 限制性 CORS 白名單 (非 `*`) |
| VULN-06 | 注入 | KQL/SPL/Sigma 查詢輸出轉義 |
| VULN-07 | 網路 | 預設綁定 localhost (127.0.0.1)，非 0.0.0.0 |
| VULN-10 | XXE | `defusedxml` 防禦 XML 外部實體攻擊 |
| VULN-14 | 供應鏈 | `pip-audit` 依賴套件漏洞掃描 |
| VULN-15 | LLM 安全 | Prompt injection 偵測與輸入清洗 |
| VULN-17 | SSRF | Ollama URL 白名單驗證 |
| VULN-19 | CSP | Content-Security-Policy 標頭 |
| VULN-20 | DoS | Per-IP 速率限制 (slowapi) |
| VULN-21 | 資訊洩漏 | 通用錯誤處理器，不暴露堆疊追蹤 |
| VULN-22 | 金鑰管理 | API Key 每次從環境變數讀取，不快取於記憶體 |
| VULN-23 | Context 注入 | LLM event_context 欄位白名單 |
| VULN-24 | Log 注入 | 檔名清洗（去除控制字元、路徑遍歷） |

### Docker 安全

- **非 root 執行**：容器內以 `bluehound` 用戶運行
- **唯讀根檔案系統**：`read_only: true` + `tmpfs` for /tmp
- **能力丟棄**：`cap_drop: ALL`
- **隔離網路**：專用 bridge 網路 `172.28.0.0/24`
- **安全標頭**：X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy

---

## 🗺️ MITRE ATT&CK 覆蓋範圍

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

## ⚙️ 環境設定

所有設定透過 `.env` 檔案或環境變數管理。完整選項請參考 [`.env.example`](.env.example)。

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `LLM_BACKEND` | `fallback` | LLM 引擎：`ollama` / `openai` / `fallback` |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 服務位址 |
| `OLLAMA_MODEL` | `llama3.2` | Ollama 模型名稱 |
| `OPENAI_API_KEY` | *(空)* | OpenAI API 金鑰 |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI 模型名稱 |
| `BLUEHOUND_HOST` | `127.0.0.1` | 伺服器綁定位址 |
| `BLUEHOUND_PORT` | `8443` | 伺服器連接埠 |
| `BLUEHOUND_API_KEY` | *(空)* | API 認證金鑰（空 = 開發模式免認證） |
| `ALLOWED_ORIGINS` | `http://localhost:8443,...` | CORS 允許來源 |
| `BLUEHOUND_MAX_PARSED_EVENTS` | `150000` | 最大解析事件數 |
| `BLUEHOUND_MAX_RESPONSE_EVENTS` | `50000` | 最大回應事件數 |

### 產生安全 API Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📝 自訂 Playbook 規則

威脅偵測規則定義在 [`playbooks/windows_hunting.yaml`](playbooks/windows_hunting.yaml) 中，格式如下：

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
    description: "說明此規則偵測什麼。"
    hunt_guidance: "提供分析師的下一步行動建議。"
```

### 支援的匹配條件

| 條件 | 類型 | 說明 |
|------|------|------|
| `process_name` | string / list | 流程名稱精確匹配 |
| `event_id` | int / list | 事件 ID 匹配 |
| `commandline_regex` | string | 命令列正則匹配 |
| `process_path_regex` | string | 流程路徑正則匹配 |
| `properties_regex` | string | AD 屬性正則匹配 (EID 4662) |
| `event_outcome` | string / list | 事件結果 (failed/success) |
| `action_type` | string / list | 動作類型 |
| `event_category` | string / list | 事件類別 |
| `parent_child_anomaly` | bool | 異常父子流程關係 |

---

## 🧰 技術棧

| 層級 | 技術 |
|------|------|
| **後端框架** | FastAPI 0.138 + Uvicorn |
| **圖學引擎** | NetworkX |
| **日誌解析** | json / csv / defusedxml / python-evtx |
| **LLM 整合** | httpx → Ollama API / OpenAI API |
| **速率限制** | slowapi |
| **前端渲染** | Vanilla JS + D3.js (力導向圖 / 時間線) |
| **容器化** | Docker multi-stage + Compose |
| **安全審計** | pip-audit |

---

## 🛠️ 開發

### 本地開發

```bash
# 安裝開發依賴
pip install -r requirements.txt

# 啟動 (含熱重載)
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8443 \
  --reload --reload-include "*.yaml" --reload-include "*.yml"
```

### 依賴安全審計

```bash
pip-audit --desc on
```

### Docker 開發模式

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml up --build
```

開發模式特性：
- 原始碼掛載為 Volume，支援熱重載
- 關閉 API Key 驗證
- 關閉唯讀檔案系統限制

---

## 📄 授權

本專案採用 MIT 授權條款。

---

<div align="center">

**Built for Blue Teamers, by Blue Teamers** 🛡️

</div>
]]>