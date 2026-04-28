# GoldenImageIQ — Copilot Instructions

This repository is **GoldenImageIQ**, a golden-image scaffolder that generates production-ready
IQ assessment platforms from a single YAML domain definition.

## What This Repo Does

`iqforge` takes a YAML file describing a domain (security, finops, devsecops, compliance, etc.)
and generates a complete repo with: AI agent, FastAPI API, collectors, evaluators, reports
(HTML/PDF/Excel/SARIF), SPA web interface, Azure deployment scripts, Teams manifest, and JSON schemas.

## How to Use iqforge

### Validate a config
```bash
python iqforge.py validate --config <yaml-file>
# or after pip install -e .
iqforge validate --config <yaml-file>
```

### Generate a project
```bash
python iqforge.py create --config <yaml-file> --output <output-dir> [--force]
# or after pip install -e .
iqforge create --config <yaml-file> --output <output-dir> [--force]
```

### Python API
```python
from iqforge import create_project, validate_config
cfg = validate_config("path/to/config.yaml")
create_project(cfg, output_dir="path/to/output")
```

## YAML Domain Definition Schema

When helping users create a YAML config, use this schema:

```yaml
# Required fields
project_name: string          # Display name, e.g. "FinOpsIQ"
base_name: string             # Resource prefix, e.g. "FinOpsIQ"
description: string           # One-line description

# Required: data sources (at least one category with at least one source)
data_sources:
  azure:                      # Azure Resource Manager API collectors
    - name: string            # snake_case, e.g. "cost_management"
      evidence_types: [str]   # List of evidence type names
      azure_sdk: string       # Optional pip package name
  graph:                      # Microsoft Graph API collectors
    - name: string
      evidence_types: [str]
  custom:                     # Custom/external collectors
    - name: string
      evidence_types: [str]

# Required: at least one framework
frameworks:
  - id: string                # e.g. "NIST-CSF-2.0"
    name: string              # e.g. "NIST Cybersecurity Framework"
    version: string           # e.g. "2.0"
    domains: [string]         # Assessment domains, e.g. ["identify", "protect"]
    controls:
      - id: string            # e.g. "PR.AC-1"
        title: string         # Control description
        domain: string        # Must be in parent framework's domains list
        severity: string      # One of: critical, high, medium, low, informational
        evaluation_logic: string  # Python function name, e.g. "check_mfa_enabled"
        evidence_types: [str] # Which evidence types this control needs

# Optional fields
reports: [html, pdf, xlsx, sarif, oscal, csv, markdown]

azure:
  location: string                  # e.g. "swedencentral"
  container_apps_location: string   # e.g. "northeurope"
  models:
    primary: string                 # e.g. "gpt-4.1"
    fallback: string                # e.g. "gpt-4.1-mini"

spa_pages:                    # Custom assessment pages for the SPA
  - name: string
    title: string

thresholds: {}                # Domain-specific score thresholds
additional_tools: []          # Extra agent tool definitions
```

## Example Configs

Three examples exist in `examples/`:
- `enterprise-security-iq.yaml` — Security, NIST CSF 2.0 + CIS Azure 3.0, 14 collectors
- `finops-iq.yaml` — FinOps, FinOps Foundation 1.0, 7 collectors
- `devsecops-iq.yaml` — DevSecOps, SLSA 1.0 + OWASP CI/CD, 6 collectors

Reference these when the user describes a similar domain.

## What Gets Generated

| Layer | Description |
|-------|-------------|
| AI Agent | FastAPI + Azure OpenAI function-calling agent with SSE streaming |
| Collectors | One module per data source, auto-discovered via @register_collector |
| Evaluators | One module per domain, severity-weighted scoring |
| Reports | HTML (Fluent 2), PDF (Playwright), Excel, SARIF |
| SPA | Vanilla JS chat + per-domain assessment pages |
| Infrastructure | 16-step PowerShell deploy (RG→ACR→Container Apps) |
| Teams | Manifest with SSO and static tabs |
| Config | JSON config + JSON Schema validation |
| Schemas | Evidence + Finding record JSON schemas |

## After Generation — What to Fill In

Tell the user they need to implement:
1. **Collector logic** — API calls in `AIAgent/app/collectors/*.py`
2. **Check functions** — Evaluation logic in `AIAgent/app/*_evaluators/*.py`
3. **Azure config** — AI Foundry hub/project, Entra app in `Infra/deploy.ps1`

Everything else works out of the box.

## Conversational Guidelines

When a user asks to create a new platform:
1. Ask what **domain** they want (security, finops, compliance, devops, custom)
2. Ask what **data sources** they need (Azure APIs, Microsoft Graph, custom)
3. Ask what **framework/standard** to assess against
4. Ask for the **controls** or offer to generate sensible defaults
5. Ask for **output location**
6. Generate the YAML, validate it, then scaffold the project
7. Summarize what was created and list the TODO stubs
