# Getting Started

> Prerequisites, installation, authentication, and running your first assessment.

## Prerequisites

- **Python 3.10+**
- Azure subscription with **Reader** + **Security Reader** roles
- Entra ID directory read permissions (for Graph collectors)
- Microsoft Foundry project with a deployed model (for agent mode only)

## Required Azure Permissions (Read-Only)

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Subscription | ARM resource enumeration and configuration reads |
| **Security Reader** | Subscription | Defender plans, security contacts, auto-provisioning |
| **Key Vault Secrets User** | Key Vault | Secret expiry data-plane audit |
| **Key Vault Certificates Officer** | Key Vault | Certificate expiry data-plane audit |
| **Key Vault Crypto User** | Key Vault | Key expiry data-plane audit |

## Required Microsoft Graph Permissions

| Permission | Purpose |
|-----------|---------|
| `Directory.Read.All` | Tenant info, OAuth2 grants, directory roles |
| `User.Read.All` | Users, group membership |
| `Group.Read.All` | Groups |
| `Application.Read.All` | App registrations, service principals |
| `RoleManagement.Read.All` | Role assignments, PIM eligibility |
| `Policy.Read.All` | CA policies, auth methods, named locations |
| `AuditLog.Read.All` | Sign-in logs, directory audits (requires Entra ID P1/P2) |
| `UserAuthenticationMethod.Read.All` | MFA registration details |
| `IdentityRiskEvent.Read.All` | Risk detections (requires Entra ID P2) |
| `IdentityRiskyUser.Read.All` | Risky users |
| `IdentityRiskyServicePrincipal.Read.All` | Risky service principals |
| `AccessReview.Read.All` | Access review definitions |
| `EntitlementManagement.Read.All` | Access packages |
| `Agreement.Read.All` | Terms of use |
| `InformationProtection.Read` | Sensitivity labels (Purview) |

## Installation

```bash
cd AIAgent
pip install -r requirements.txt
```

## Authentication

PostureIQ uses a unified `DefaultAzureCredential` for both ARM and Graph operations.

```bash
az login
```

| Mode | Configuration |
|------|---------------|
| **Auto** (default) | `az login` — used for both ARM and Graph |
| **ServicePrincipal** | Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |

A preflight permissions check runs before each assessment to verify ARM access, Graph connectivity, and Entra directory roles.

## Run Your First Assessment

### Option 1 — CLI

```bash
cd AIAgent
python run_assessment.py --tenant <your-tenant-id> --framework NIST-800-53 CIS
```

### Option 2 — AI Agent (Foundry)

```bash
cd AIAgent
python main.py
# Agent server starts on http://localhost:8088
```

### Option 3 — GitHub Copilot Chat

```
provide Assessment on tenant "<TenantID>", using account "<UPN>" based on NIST, CIS, HIPAA, PCI-DSS, FedRAMP, SOC
```

> Ensure you have already authenticated with `az login --tenant <TenantID>` before running the prompt.

## Review Output

Assessment results are written to `output/<timestamp>/`:

| File | Description |
|------|-------------|
| `compliance-report.html` | Interactive HTML report with sidebar nav, score ring, domain cards, framework summaries, remediation roadmap |
| `compliance-report.json` | Structured JSON with all findings, evidence, and framework metadata |

Additional formats (Markdown, Excel, OSCAL, SARIF, PDF) are generated when configured.

## Available CLI Scripts

| Script | Purpose |
|--------|---------|
| `run_assessment.py` | Full compliance assessment |
| `run_query.py` | Interactive ARG/Graph query REPL |
| `run_risk_analysis.py` | Security risk gap analysis |
| `run_data_security.py` | Data security assessment |
| `run_rbac_report.py` | RBAC hierarchy report |
| `run_copilot_readiness.py` | M365 Copilot readiness assessment |
| `run_ai_agent_security.py` | AI agent security assessment |

### Determinism Validators

These scripts run the same assessment twice with identical inputs and verify that outputs are byte-identical:

| Script | Validates |
|--------|-----------|
| `run_assessment_determinism_check.py` | Full assessment pipeline |
| `run_rbac_determinism_check.py` | RBAC report pipeline |
| `run_cr_determinism_check.py` | Copilot readiness pipeline |
| `run_aias_determinism_check.py` | AI agent security pipeline |
| `run_postureiq_determinism_check.py` | PostureIQ engine pipeline |
| `run_risk_determinism_check.py` | Risk analysis pipeline |
| `run_ds_determinism_check.py` | Data security pipeline |

## Next Steps

- [Architecture](architecture.md) — understand the pipeline design
- [Configuration](configuration.md) — customize frameworks, thresholds, and outputs
- [Assessment Engines](assessment-engines.md) — explore all 7 standalone engines
