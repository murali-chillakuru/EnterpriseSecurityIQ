# IQForge — Template Scaffolder for IQ-Platforms

**IQForge** takes a single YAML domain definition and generates a complete, production-ready
assessment platform with the same architecture as EnterpriseSecurityIQ — but for **any domain**.

## What It Generates

From one YAML file, IQForge produces a full repo:

| Layer | What you get |
|-------|-------------|
| **AI Agent** | FastAPI + Azure OpenAI function-calling agent with SSE streaming |
| **Collectors** | One module per data source — auto-discovered via `@register_collector` |
| **Evaluators** | One module per domain — severity-weighted scoring, deterministic finding IDs |
| **Reports** | HTML (self-contained, Fluent 2 theme), PDF (Playwright), Excel, SARIF |
| **SPA** | Vanilla JS + SSE chat interface + per-domain assessment pages |
| **Infrastructure** | 16-step PowerShell deployment (RG → ACR → Container Apps) |
| **Teams** | Manifest with SSO, static tabs per assessment page |
| **Config** | JSON config + JSON Schema validation |
| **Schemas** | Evidence + Finding record JSON Schemas |

## Quick Start

```bash
# Prerequisites
pip install jinja2 pyyaml

# Validate a domain definition
python iqforge.py validate --config examples/finops-iq.yaml

# Generate a new platform
python iqforge.py create --config examples/finops-iq.yaml --output ../FinOpsIQ
```

## Three-Tier File Strategy

IQForge uses three tiers of file generation:

### 1. Copy Tier (~12 files)
Domain-agnostic files copied verbatim — these are the same regardless of domain:
- `blob_store.py` — Azure Blob Storage helper
- `logger.py` — JSON structured logging
- `collectors/registry.py` — Auto-discovery with `@register_collector`
- `collectors/base.py` — `make_evidence()` factory
- `core/models.py` — `EvidenceRecord`, `FindingRecord`, `AssessmentResult`
- `reports/*` — PDF, Excel, SARIF, raw data exporters
- `Dockerfile` — Multi-stage container build

### 2. Parameterized Tier (~14 .j2 templates)
Jinja2 templates with `{{project_name}}`, `{{domains}}`, `{{tools}}` placeholders:
- `main.py.j2` → Entry point
- `api.py.j2` → FastAPI routes with SSE
- `agent.py.j2` → AI agent with auto-generated tool functions
- `orchestrator.py.j2` → Collect → Evaluate → Report pipeline
- `engine.py.j2` → Evaluation engine with cross-domain fallback
- `config.py.j2` → Configuration loader
- `deploy.ps1.j2` → Azure deployment script
- `index.html.j2` → SPA home page
- `readme.md.j2` → Generated README

### 3. Generated Tier (N per domain/framework/datasource)
One file per entity in the YAML definition:
- `collector.py.j2` → One collector per data source
- `evaluator.py.j2` → One evaluator per domain
- `framework-mapping.json.j2` → One mapping file per framework
- `assessment-page.html.j2` → One SPA page per configured page

## Domain Definition YAML Schema

```yaml
project_name: string          # Display name (e.g., "FinOpsIQ")
base_name: string             # Resource prefix (e.g., "FinOpsIQ")
description: string           # Project description

data_sources:
  azure:                      # Azure Resource Manager collectors
    - name: string
      evidence_types: [string]
      azure_sdk: string       # Optional: pip package name
  graph:                      # Microsoft Graph collectors
    - name: string
      evidence_types: [string]
  custom:                     # Custom/external collectors
    - name: string
      evidence_types: [string]

frameworks:
  - id: string                # e.g., "NIST-CSF-2.0"
    name: string
    version: string
    domains: [string]         # Assessment domains
    controls:
      - id: string            # e.g., "PR.AC-1"
        title: string
        domain: string        # Must be in parent domains list
        severity: critical|high|medium|low|informational
        evaluation_logic: string  # Python function name
        evidence_types: [string]  # Required evidence to evaluate

reports: [html, pdf, xlsx, sarif, oscal, csv, markdown]

azure:
  location: string            # e.g., "swedencentral"
  container_apps_location: string
  models:
    primary: string           # e.g., "gpt-4.1"
    fallback: string

spa_pages:                    # Optional: custom assessment pages
  - name: string
    title: string

thresholds: {}                # Optional: domain-specific thresholds
additional_tools: []          # Optional: extra agent tools
```

## Examples

| Example | Domain | Frameworks | Collectors |
|---------|--------|------------|------------|
| [enterprise-security-iq.yaml](examples/enterprise-security-iq.yaml) | Security | NIST CSF 2.0, CIS Azure 3.0 | 14 (Azure + Graph) |
| [finops-iq.yaml](examples/finops-iq.yaml) | FinOps | FinOps Foundation 1.0 | 7 (Azure + Custom) |
| [devsecops-iq.yaml](examples/devsecops-iq.yaml) | DevSecOps | SLSA 1.0, OWASP CI/CD | 6 (Azure + Graph + Custom) |

## After Generation — What to Fill In

The generator creates the complete scaffold. You need to implement:

1. **Collector logic** (`AIAgent/app/collectors/`) — API calls to fetch evidence
2. **Check functions** (`AIAgent/app/<name>_evaluators/`) — Evaluation logic per control
3. **Azure config** (`Infra/deploy.ps1`) — AI Foundry hub/project, Entra app registration

Everything else (API, agent, reports, SPA, Docker, schemas) works out of the box.

## Project Structure

```
ExportAgent2Zip/Template/
├── iqforge.py                # CLI entry point (create / validate)
├── iqforge/
│   ├── __init__.py
│   ├── generator.py          # Core scaffolding engine
│   ├── validators.py         # YAML schema validation
│   └── file_registry.py      # File tier tracking
├── templates/
│   ├── copy/                 # Tier 1: verbatim copy files
│   ├── parameterized/        # Tier 2: Jinja2 templates
│   └── stubs/                # Tier 3: per-entity generators
├── examples/                 # Example domain definitions
│   ├── enterprise-security-iq.yaml
│   ├── finops-iq.yaml
│   └── devsecops-iq.yaml
└── README.md                 # This file
```

## Requirements

- Python 3.11+
- `pip install jinja2 pyyaml`

## Architecture Patterns (from ESIQ)

IQForge encodes these proven patterns from EnterpriseSecurityIQ:

- **Agent**: Plain `async def` tools, TOOL_SCHEMAS manual JSON, max 10 function-calling rounds
- **Collectors**: `@register_collector` decorator, `pkgutil` auto-discovery, `make_evidence()` factory
- **Evaluators**: Domain→function mapping, severity-weighted scoring, UUID5 deterministic IDs
- **Reports**: Self-contained HTML (inline CSS/JS), Playwright PDF, openpyxl Excel, SARIF 2.1.0
- **API**: FastAPI SSE streaming, path traversal protection, CORS
- **SPA**: Vanilla JS + fetch ReadableStream, Fluent 2 theme
- **Blob**: DefaultAzureCredential, local-first → upload → blob fallback
- **Infra**: 16-step deploy.ps1 (RG→Foundry→Models→Storage→KV→LAW→ACR→Identity→RBAC→ContainerApp)
- **Docker**: Private ACR base, Playwright, non-root user, healthcheck
