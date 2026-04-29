# PostureIQ Documentation

> AI-powered compliance intelligence for Azure, Microsoft Entra ID, M365 Copilot, and AI Agent platforms.

**64 Collectors · 11 Frameworks · 525 Controls · 130+ Check Functions · 10 Domains · 14 Agent Tools · 8 Report Formats · 8 Engines**

## What PostureIQ Does

PostureIQ is a **read-only** compliance assessment platform. It discovers Azure resources and Microsoft Entra configurations, collects evidence from control-plane and data-plane APIs, maps findings to compliance frameworks, evaluates your security posture, and generates professional auditor-ready reports.

> **Safety guarantee:** PostureIQ never creates, modifies, or deletes any tenant resource.

### Three-Phase Pipeline

| Phase | What Happens | Details |
|-------|-------------|---------|
| **1. Collect** | 64 collectors gather evidence | 52 Azure (ARM, data-plane) + 12 Entra (Graph) collectors run concurrently |
| **2. Evaluate** | 130+ check functions assess controls | 525 controls across 10 security domains, severity-weighted scoring |
| **3. Report** | Generators produce output | HTML, JSON, Markdown, Excel, OSCAL, SARIF, PDF, and Webhook formats |

Runs as a **Microsoft Foundry AI Agent** (conversational, 14 tools) or as **standalone CLI scripts** (headless, CI/CD-ready).

## Documents

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Prerequisites, installation, authentication, and first assessment |
| [Architecture](architecture.md) | Pipeline design, data flow, collector → evaluator → report |
| [Deployment](deployment.md) | Container build, Azure Container Apps, CI/CD pipelines |
| [Configuration](configuration.md) | Environment variables, JSON config, thresholds, suppressions |
| [Assessment Engines](assessment-engines.md) | All 8 engines — capabilities, categories, and usage |
| [Extending](extending.md) | Adding custom frameworks, evaluators, collectors, and report formats |
| [Coverage Matrix](coverage-matrix.html) | Interactive grid of all frameworks, domains, and controls |

## Capabilities

| Capability | Agent Tool | CLI Script | Description |
|-----------|-----------|-----------|-------------|
| Security Compliance Assessment | `run_assessment` | `run_assessment.py` | Full multi-framework assessment across 10 domains |
| Cloud Explorer | `search_tenant` | `run_query.py` | Live Azure Resource Graph and MS Graph queries |
| Risk Assessment | `analyze_risk` | `run_risk_analysis.py` | Security risk gap analysis across 4 categories |
| Data Security Assessment | `assess_data_security` | `run_data_security.py` | Data-layer posture: storage, DB, encryption, classification |
| RBAC Assessment | `generate_rbac_report` | `run_rbac_report.py` | Interactive RBAC hierarchy tree with PIM and risk analysis |
| Copilot Readiness Assessment | `assess_copilot_readiness` | `run_copilot_readiness.py` | M365 Copilot readiness: oversharing, DLP, governance |
| AI Agent Security Assessment | `assess_ai_agent_security` | `run_ai_agent_security.py` | Security posture for Copilot Studio, Foundry, custom agents |
| PostureIQ Assessment | `run_postureiq_assessment` | — | Risk-weighted scoring with attack paths and AI fix recommendations |
| Query Results | `query_results` | — | Search cached findings by control, domain, or severity |
| Report Generation | `generate_report` | — | Regenerate reports from cached assessment results |
| Permission Check | `check_permissions` | — | Preflight verification of ARM/Graph/Entra permissions |
| Run Comparison | `compare_runs` | — | Delta comparison: new/resolved findings, score drift |
| Exposure Search | `search_exposure` | — | Quick-scan of public-facing resources and sensitive data |
| Custom Report | `generate_custom_report` | — | Custom-scoped reports with selected frameworks and formats |

## Supported Frameworks

| Framework | Controls |
|-----------|---------|
| NIST 800-53 Rev 5 | 83 |
| FedRAMP Moderate | 69 |
| CIS Azure Benchmark v2.0 | 53 |
| Microsoft Cloud Security Benchmark | 53 |
| PCI DSS v4.0 | 51 |
| ISO 27001:2022 | 51 |
| SOC 2 Type II | 47 |
| HIPAA Security Rule | 43 |
| NIST Cybersecurity Framework | 29 |
| CSA Cloud Controls Matrix | 24 |
| GDPR | 22 |

## Quick Links

- **Repository root:** [README](../README.md)
- **Agent README:** [AIAgent/README](../AIAgent/README.md)
- **Changelog:** [CHANGELOG](../CHANGELOG.md)
