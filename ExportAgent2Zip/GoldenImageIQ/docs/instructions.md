# GoldenImageIQ — Setup & Usage Instructions

## What is GoldenImageIQ?

GoldenImageIQ is a **golden-image scaffolder** that generates complete, production-ready
assessment platforms from a single YAML domain definition. It encodes proven architecture
patterns from EnterpriseSecurityIQ so any domain (Security, FinOps, DevSecOps, Compliance,
Supply-Chain, etc.) gets the identical architecture, UX, infrastructure, and operational model.

---

## Prerequisites

- **Python 3.11+**
- **pip** (comes with Python)
- **VS Code** with GitHub Copilot extension (for conversational mode)

---

## Setup — Copy to Your Repo

### Option A: Copy the GoldenImageIQ folder

```powershell
# Copy to a new repo location
Copy-Item -Recurse -Path .\ExportAgent2Zip\GoldenImageIQ -Destination C:\Repos\GoldenImageIQ
cd C:\Repos\GoldenImageIQ

# Initialize as a git repo (optional)
git init
git add .
git commit -m "Initial golden image setup"
```

### Option B: Clone from a shared repo
```powershell
git clone <your-golden-image-repo-url> C:\Repos\GoldenImageIQ
cd C:\Repos\GoldenImageIQ
```

---

## Install as a CLI Tool

```powershell
cd C:\Repos\GoldenImageIQ
pip install -e .
```

After install, `iqforge` is available as a command from anywhere on your system.

---

## Three Ways to Use

### Way 1: Conversational via GitHub Copilot (Recommended)

1. Open the `GoldenImageIQ` folder in VS Code
2. Open **Copilot Chat** (Ctrl+Shift+I)
3. Type `/scaffold-project` and press Enter
4. Copilot will ask you step-by-step:
   - What domain? (security, finops, devsecops, compliance, custom)
   - What data sources? (Azure APIs, Graph, custom)
   - What frameworks/standards?
   - What controls?
   - Where to output?
5. Copilot generates the YAML, validates it, scaffolds the project, and summarizes

### Way 2: CLI

```powershell
# Validate a domain definition
iqforge validate --config examples/finops-iq.yaml

# Scaffold a new project
iqforge create --config examples/finops-iq.yaml --output C:\Repos\FinOpsIQ

# Or without installing:
python iqforge.py validate --config examples/finops-iq.yaml
python iqforge.py create --config examples/finops-iq.yaml --output C:\Repos\FinOpsIQ
```

### Way 3: Python API

```python
from iqforge import create_project, validate_config

cfg = validate_config("examples/finops-iq.yaml")
create_project(cfg, output_dir="C:/Repos/FinOpsIQ")
```

---

## Writing a Domain Definition YAML

Create a YAML file describing your assessment platform. Here's the minimal structure:

```yaml
project_name: "MyPlatformIQ"
base_name: "MyPlatformIQ"
description: "Assessment platform for my domain"

data_sources:
  azure:
    - name: my_data_source
      evidence_types: [my_evidence_type]

frameworks:
  - id: "MY-FRAMEWORK-1.0"
    name: "My Framework"
    version: "1.0"
    domains: [domain_a, domain_b]
    controls:
      - id: "DA-1"
        title: "My first control"
        domain: domain_a
        severity: high
        evaluation_logic: check_my_control
        evidence_types: [my_evidence_type]
```

### Full Schema Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `project_name` | Yes | string | Display name (e.g., "FinOpsIQ") |
| `base_name` | Yes | string | Resource prefix for Azure naming |
| `description` | Yes | string | One-line project description |
| `data_sources` | Yes | object | Categories: `azure`, `graph`, `custom` |
| `data_sources.<type>[].name` | Yes | string | Snake_case collector name |
| `data_sources.<type>[].evidence_types` | Yes | list | Evidence type identifiers |
| `data_sources.<type>[].azure_sdk` | No | string | pip package for azure sources |
| `frameworks` | Yes | list | At least one framework |
| `frameworks[].id` | Yes | string | Framework identifier |
| `frameworks[].name` | Yes | string | Framework display name |
| `frameworks[].version` | Yes | string | Framework version |
| `frameworks[].domains` | Yes | list | Assessment domain names |
| `frameworks[].controls` | Yes | list | At least one control |
| `frameworks[].controls[].id` | Yes | string | Control identifier |
| `frameworks[].controls[].title` | Yes | string | Control description |
| `frameworks[].controls[].domain` | Yes | string | Must exist in parent domains |
| `frameworks[].controls[].severity` | Yes | string | critical/high/medium/low/informational |
| `frameworks[].controls[].evaluation_logic` | Yes | string | Python function name |
| `frameworks[].controls[].evidence_types` | Yes | list | Required evidence types |
| `reports` | No | list | Output formats: html, pdf, xlsx, sarif, oscal, csv, markdown |
| `azure` | No | object | Azure location and model config |
| `spa_pages` | No | list | Custom SPA assessment pages |
| `thresholds` | No | object | Domain-specific score thresholds |
| `additional_tools` | No | list | Extra agent tool definitions |

### Severity Values
- `critical` — Weight 1.0
- `high` — Weight 0.8
- `medium` — Weight 0.5
- `low` — Weight 0.2
- `informational` — Weight 0.0

### Data Source Types
- `azure` — Azure Resource Manager APIs (gets DefaultAzureCredential + subscription iteration)
- `graph` — Microsoft Graph APIs (gets DefaultAzureCredential)
- `custom` — External/custom sources (gets kwargs)

---

## What Gets Generated

Running `iqforge create` produces this structure:

```
<output>/
├── AIAgent/
│   ├── main.py              ← Entry point
│   ├── Dockerfile            ← Container build
│   ├── requirements.txt      ← Dependencies
│   ├── app/
│   │   ├── agent.py          ← AI function-calling agent
│   │   ├── api.py            ← FastAPI + SSE routes
│   │   ├── orchestrator.py   ← Collect → Evaluate → Report pipeline
│   │   ├── engine.py         ← Evaluation engine
│   │   ├── config.py         ← Configuration loader
│   │   ├── blob_store.py     ← Azure Blob Storage helper
│   │   ├── logger.py         ← JSON structured logging
│   │   ├── collectors/       ← One file per data source (stubs)
│   │   ├── <domain>_evaluators/ ← One file per domain (stubs)
│   │   ├── frameworks/       ← One JSON mapping per framework
│   │   ├── core/models.py    ← EvidenceRecord, FindingRecord
│   │   └── reports/          ← HTML, PDF, Excel, SARIF exporters
├── webapp/                   ← SPA chat + assessment pages
├── Infra/deploy.ps1          ← 16-step Azure deployment
├── config/                   ← JSON config + schema
├── teams/                    ← Teams app manifest
├── schemas/                  ← JSON schemas
├── docs/, examples/, output/
```

---

## After Generation — What to Fill In

Only three areas need implementation:

### 1. Collectors (`AIAgent/app/collectors/`)
Each collector has a `collect()` function stub. Implement the API calls:

```python
async def collect(credential, subscriptions: list[str]) -> list[dict]:
    # TODO: Call Azure/Graph/custom APIs and return evidence records
    return [make_evidence("my_evidence_type", resource_id, data)]
```

### 2. Evaluators (`AIAgent/app/<domain>_evaluators/`)
Each evaluator has check functions matching your controls:

```python
def check_my_control(evidence: list[dict], **kwargs) -> list[dict]:
    # TODO: Evaluate evidence and return finding records
    findings = []
    for e in evidence:
        # Your evaluation logic here
        pass
    return findings
```

### 3. Azure Config (`Infra/deploy.ps1`)
Update the deployment script with your:
- AI Foundry hub and project names
- Entra app registration IDs
- Resource naming preferences

**Everything else (API, agent, reports, SPA, Docker, schemas) works out of the box.**

---

## Example Configs

| Example | Domain | Frameworks | Collectors | Location |
|---------|--------|------------|------------|----------|
| Enterprise Security | Security | NIST CSF 2.0, CIS Azure 3.0 | 14 | `examples/enterprise-security-iq.yaml` |
| FinOps | Cloud FinOps | FinOps Foundation 1.0 | 7 | `examples/finops-iq.yaml` |
| DevSecOps | DevSecOps | SLSA 1.0, OWASP CI/CD | 6 | `examples/devsecops-iq.yaml` |

---

## Architecture Patterns

IQForge encodes these production-proven patterns:

| Pattern | Implementation |
|---------|---------------|
| AI Agent | Plain `async def` tools, manual TOOL_SCHEMAS JSON, max 10 rounds |
| Collectors | `@register_collector` decorator, `pkgutil` auto-discovery |
| Evaluators | Domain→function mapping, severity-weighted scoring, UUID5 deterministic IDs |
| Reports | Self-contained HTML (inline CSS/JS), Playwright PDF, openpyxl Excel, SARIF 2.1.0 |
| API | FastAPI SSE streaming, path traversal protection, CORS |
| SPA | Vanilla JS + fetch ReadableStream, Fluent 2 theme |
| Blob | DefaultAzureCredential, local-first → upload → blob fallback |
| Infra | 16-step deploy.ps1 (RG→Foundry→Models→Storage→KV→ACR→Identity→RBAC→ContainerApp) |
| Docker | Private ACR base, Playwright, non-root user, healthcheck |

---

## Troubleshooting

| Issue | Solution |
|-------|---------|
| `iqforge` command not found | Run `pip install -e .` from the GoldenImageIQ directory |
| `ERROR: PyYAML is required` | Run `pip install pyyaml` |
| `ERROR: Jinja2 is required` | Run `pip install jinja2` |
| Validation fails | Check YAML syntax, ensure all required fields are present |
| `/scaffold-project` not showing | Open the GoldenImageIQ folder as workspace root in VS Code |
