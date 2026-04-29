# API Reference

> All HTTP endpoints, request/response formats, and Server-Sent Events protocol.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · **API Reference** · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## Base URL

```
https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io
```

All endpoints require HTTPS. HTTP requests are redirected to HTTPS by the Container Apps ingress.

---

## Endpoints

| # | Method | Path | Auth | Purpose |
|---|--------|------|------|---------|
| 1 | `GET` | `/` | None | Serve the SPA dashboard |
| 2 | `POST` | `/chat` | Required | Agent chat with SSE streaming |
| 3 | `POST` | `/assessments` | Required | Start background assessment |
| 4 | `GET` | `/assessments/{id}` | Required | Poll assessment status |
| 5 | `GET` | `/reports` | None | List all available reports |
| 6 | `GET` | `/reports/{file_path}` | None | Download a specific report |
| 7 | `GET` | `/health` | None | Health check |

---

## 1. GET / — SPA Dashboard

Serves the main single-page application.

**Request:**
```http
GET / HTTP/1.1
Host: esiqnew-agent.....azurecontainerapps.io
```

**Response:** HTML page (the assessment dashboard)

The SPA JavaScript handles all routing client-side. Different assessment pages (`SecurityComplianceAssessment.html`, `DataSecurity.html`, etc.) are served as separate HTML files from the `/` mount.

---

## 2. POST /chat — Agent Chat (SSE)

The primary endpoint. Sends a message to the AI agent and receives a streaming response with tool execution updates and report URLs.

### Request

```http
POST /chat HTTP/1.1
Content-Type: application/json

{
  "message": "Run PostureIQ assessment for FedRAMP and CIS",
  "graph_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "arm_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "page": "SecurityComplianceAssessment",
  "conversation_id": "abc123-def456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | string | Yes | User's message or assessment request |
| `graph_token` | string | Yes | Microsoft Graph access token (delegated) |
| `arm_token` | string | Yes | Azure Resource Manager access token (delegated) |
| `page` | string | No | Current page name (controls which tools are available) |
| `conversation_id` | string | No | Session ID for multi-turn conversations |

### Response (Server-Sent Events)

The response is a stream of SSE events:

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

: keepalive

data: {"type":"tool","name":"run_postureiq_assessment","status":"running"}

: keepalive

: keepalive

data: {"type":"tool","name":"run_postureiq_assessment","status":"done"}

data: {"type":"report_table","rows":[{"framework":"FedRAMP","html":"/reports/20260422/.../fedramp-compliance-report.html","pdf":"/reports/20260422/.../fedramp-compliance-report.pdf","xlsx":"/reports/20260422/.../fedramp-compliance-report.xlsx","json":"/reports/20260422/.../fedramp-compliance.json"}],"shared":[{"name":"Data Exports","url":"/reports/20260422/.../data_exports/"}],"zip":"/reports/20260422/.../all-postureiq-reports.zip"}

data: {"type":"token_usage","prompt_tokens":15234,"completion_tokens":2841,"total_tokens":18075,"estimated_cost_usd":0.0642}

data: {"response":"## PostureIQ Assessment Complete\n\n### Executive Summary\nYour FedRAMP compliance score is **78.5%**...\n\n","tools_used":["run_postureiq_assessment"]}

```

### SSE Event Types

| Event Type | Format | When |
|-----------|--------|------|
| `keepalive` | `: keepalive\n\n` | Every 15 seconds during tool execution |
| `tool` | `{"type":"tool","name":"...","status":"running\|done"}` | When a tool starts or finishes |
| `report` | `{"type":"report","name":"...","url":"..."}` | Individual report file URL |
| `report_table` | `{"type":"report_table","rows":[...],"shared":[...],"zip":"..."}` | Structured table of all reports |
| `token_usage` | `{"type":"token_usage","prompt_tokens":...,"estimated_cost_usd":...}` | Token usage and cost |
| `response` | `{"response":"...","tools_used":[...]}` | Final LLM response (Markdown) |
| `error` | `{"error":"..."}` | On failure |

### Error Responses

| Status | When |
|--------|------|
| `401` | Missing or invalid `graph_token` / `arm_token` |
| `400` | Missing `message` field |
| `500` | Internal server error (LLM failure, tool crash) |

### Tool Isolation by Page

The `page` field controls which tools the agent can use. This prevents irrelevant tool calls:

| Page | Available Tools |
|------|----------------|
| `SecurityComplianceAssessment` | `run_postureiq_assessment`, `query_results`, `compare_runs`, `query_assessment_history`, `generate_report`, `generate_custom_report` |
| `DataSecurity` | `assess_data_security`, `query_results`, `generate_report` |
| `RiskAnalysis` | `analyze_risk`, `query_results`, `generate_report` |
| `CopilotReadiness` | `assess_copilot_readiness`, `query_results`, `generate_report` |
| `AIAgentSecurity` | `assess_ai_agent_security`, `query_results`, `generate_report` |
| `RBACReport` | `generate_rbac_report`, `query_results` |
| `CloudExplorer` | `search_tenant`, `search_exposure`, `check_permissions` |

### Keepalive Mechanism

Long-running assessments (2–5 minutes) would normally trigger a 504 Gateway Timeout from the Envoy proxy. The keepalive mechanism prevents this:

```
Tool starts executing (in background coroutine)
    │
    while tool is running:
    │   ├── Wait 15 seconds
    │   ├── Send ": keepalive\n\n" (SSE comment)
    │   └── Repeat
    │
    Tool finishes
    └── Send tool results, report table, response
```

The `: keepalive` lines are SSE comments — they're ignored by `EventSource` clients but keep the HTTP connection alive.

### Max Tool Rounds

The agent can call up to **10 tools** per chat request. Each tool call is a separate LLM round:

```
Round 1: LLM decides to call tool A → execute → return results
Round 2: LLM decides to call tool B → execute → return results
...
Round 10: Max reached → LLM forced to produce final response
```

### Tool Result Truncation

Tool results are truncated to **4,000 characters** before being fed back to the LLM. This prevents context overflow. The full results are kept in session state for `query_results`.

Report table JSON (`<!--REPORT_TABLE:...-->`) is stripped from the LLM context after being emitted via SSE, saving tokens.

---

## 3. POST /assessments — Start Background Assessment

Starts an assessment in the background and returns an ID for polling.

### Request

```http
POST /assessments HTTP/1.1
Content-Type: application/json

{
  "type": "postureiq",
  "frameworks": ["FedRAMP", "CIS"],
  "graph_token": "eyJ...",
  "arm_token": "eyJ..."
}
```

### Response

```json
{
  "assessment_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "started",
  "type": "postureiq"
}
```

---

## 4. GET /assessments/{id} — Poll Assessment Status

### Request

```http
GET /assessments/a1b2c3d4-e5f6-7890-abcd-ef1234567890 HTTP/1.1
```

### Response (In Progress)

```json
{
  "assessment_id": "a1b2c3d4...",
  "status": "running",
  "progress": {
    "stage": "collecting",
    "completed_collectors": 42,
    "total_collectors": 64
  }
}
```

### Response (Complete)

```json
{
  "assessment_id": "a1b2c3d4...",
  "status": "completed",
  "results": {
    "score": 78.5,
    "findings_count": 47,
    "reports": [...]
  }
}
```

---

## 5. GET /reports — List All Reports

Returns a list of all available report files from both local filesystem and blob storage.

### Request

```http
GET /reports HTTP/1.1
```

### Response

```json
[
  {
    "name": "fedramp-compliance-report.html",
    "path": "20260422_023002_PM/FedRAMP/fedramp-compliance-report.html",
    "url": "/reports/20260422_023002_PM/FedRAMP/fedramp-compliance-report.html",
    "size": 245760
  },
  {
    "name": "fedramp-compliance-report.pdf",
    "path": "20260422_023002_PM/FedRAMP/fedramp-compliance-report.pdf",
    "url": "/reports/20260422_023002_PM/FedRAMP/fedramp-compliance-report.pdf",
    "size": 512000
  }
]
```

**Filters:** Only returns files with extensions: `.html`, `.json`, `.xlsx`, `.pdf`, `.csv`, `.zip`

---

## 6. GET /reports/{file_path} — Download Report

Serves a specific report file. Uses a local-first, blob-fallback strategy.

### Request

```http
GET /reports/20260422_023002_PM/FedRAMP/fedramp-compliance-report.html HTTP/1.1
```

### Response

The raw file content with appropriate MIME type.

### Path Traversal Protection

The endpoint includes path traversal protection:
1. `resolve()` the requested path to an absolute path
2. `relative_to()` check ensures it's under the output directory
3. Rejects any path containing `..` or pointing outside the allowed directory

### Fallback Logic

```
1. Check /agent/output/{file_path}
   └── Found? → Serve with correct MIME type

2. Not found locally?
   └── Download from blob: esiqnewstorage/reports/{file_path}
       └── Save to local filesystem
           └── Serve from local

3. Not in blob either?
   └── 404 {"detail": "Report not found"}
```

---

## 7. GET /health — Health Check

### Request

```http
GET /health HTTP/1.1
```

### Response

```json
{
  "status": "healthy"
}
```

Used by Container Apps as a liveness/readiness probe. The Dockerfile sets:
```dockerfile
HEALTHCHECK CMD curl -f http://localhost:8088/health || exit 1
```

---

## CORS Configuration

```python
ALLOWED_ORIGINS = [
    "https://teams.microsoft.com",
    "https://*.office.com",
    "https://*.cloud.microsoft",
    "https://*.microsoft365.com",
    "http://localhost:8080"
]
```

All origins receive full CORS support (credentials, all methods, all headers).

---

## Content Security Policy

The container app is configured with CSP headers for Teams iframe embedding:

```
frame-ancestors: https://teams.microsoft.com https://*.office.com https://*.cloud.microsoft
```

This allows the SPA to be embedded in a Teams tab while preventing embedding from unknown origins.

---

## Token Cost Tracking

Each chat request tracks token usage and returns an estimated cost:

| Metric | Source |
|--------|--------|
| `prompt_tokens` | Azure OpenAI response |
| `completion_tokens` | Azure OpenAI response |
| `total_tokens` | Sum of prompt + completion |
| `estimated_cost_usd` | `prompt_tokens × TOKEN_COST_INPUT_PER_M / 1M + completion_tokens × TOKEN_COST_OUTPUT_PER_M / 1M` |

The cost rates are configurable via environment variables:
- `TOKEN_COST_INPUT_PER_M` — Cost per million input tokens (default depends on model)
- `TOKEN_COST_OUTPUT_PER_M` — Cost per million output tokens

---

**Next:** [Teams Integration →](07-teams-integration.md)
