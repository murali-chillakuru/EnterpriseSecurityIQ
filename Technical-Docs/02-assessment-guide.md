# Assessment Guide

> Every assessment type, what it evaluates, and what happens behind the scenes.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · **Assessments** · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## Assessment Types Overview

PostureIQ provides 8 assessment engines, each accessible from a dedicated web page:

| # | Assessment | Web Page | Agent Tool | CLI Script |
|---|-----------|----------|------------|------------|
| 1 | **PostureIQ** | `SecurityComplianceAssessment.html` | `run_postureiq_assessment` | `run_postureiq_determinism_check.py` |
| 2 | **Risk Analysis** | `RiskAnalysis.html` | `analyze_risk` | `run_risk_analysis.py` |
| 3 | **Data Security** | `DataSecurity.html` | `assess_data_security` | `run_data_security.py` |
| 4 | **Copilot Readiness** | `CopilotReadiness.html` | `assess_copilot_readiness` | `run_copilot_readiness.py` |
| 5 | **AI Agent Security** | `AIAgentSecurity.html` | `assess_ai_agent_security` | `run_ai_agent_security.py` |
| 6 | **RBAC Report** | `RBACReport.html` | `generate_rbac_report` | `run_rbac_report.py` |
| 7 | **Cloud Explorer** | `CloudExplorer.html` | `search_tenant` | `run_query.py` |
| 8 | **PostureIQ (Teams)** | `Teams-SecurityComplianceAssessment.html` | `run_postureiq_assessment` | — |

Additional utility tools (not standalone assessments):

| Tool | Purpose |
|------|---------|
| `query_results` | Query previously-collected assessment data |
| `generate_report` | Generate reports from session data |
| `check_permissions` | Probe Azure/Graph permission levels |
| `compare_runs` | Compare two assessment runs (delta analysis) |
| `search_exposure` | Find publicly exposed resources |
| `query_assessment_history` | Audit trail and trend analysis |
| `generate_custom_report` | Build a focused custom report |

---

## How an Assessment Works (Step by Step)

When you click "Run Assessment" on any web page, here is the complete sequence:

```
┌──────────┐     POST /chat          ┌──────────────┐
│  Browser  │ ──────────────────────► │   api.py     │
│  (SPA)    │   { message,           │   (FastAPI)  │
│           │     graph_token,       │              │
│           │     arm_token,         │              │
│           │     page }             │              │
└──────────┘                         └──────┬───────┘
                                            │
                              Validate tokens (401 if missing)
                              Create UserTokenCredential
                              Build LLM messages
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │  Azure OpenAI  │
                                    │  (gpt-5.1)    │
                                    │               │
                                    │  "Which tool  │
                                    │   should I    │
                                    │   call?"      │
                                    └───────┬───────┘
                                            │
                              LLM returns tool_call:
                              run_postureiq_assessment(
                                frameworks="FedRAMP,CIS"
                              )
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │  Agent Tool    │
                                    │  Execution     │
                                    │               │
                                    │  1. Preflight  │
                                    │  2. Collect    │
                                    │  3. Evaluate   │
                                    │  4. Score      │
                                    │  5. Reports    │
                                    │  6. Upload     │
                                    └───────┬───────┘
                                            │
                              Return results to LLM
                              LLM formats executive summary
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │  SSE Stream    │
                                    │  to Browser    │
                                    │               │
                                    │  - tool status │
                                    │  - report URLs │
                                    │  - summary     │
                                    │  - token usage │
                                    └───────────────┘
```

---

## 1. PostureIQ Assessment (Full Security Posture)

**What it evaluates:** Your entire Azure and Entra ID security posture against compliance frameworks.

**Supported frameworks (11):**

| Framework | Controls | Focus |
|-----------|----------|-------|
| NIST 800-53 | ~60 | US federal information systems |
| FedRAMP | ~50 | US government cloud compliance |
| CIS | ~45 | Industry security benchmarks |
| MCSB | ~50 | Microsoft Cloud Security Benchmark |
| PCI DSS | ~45 | Payment card data protection |
| ISO 27001 | ~50 | International security management |
| SOC 2 | ~40 | Service organization controls |
| HIPAA | ~40 | Healthcare data protection |
| NIST CSF | ~45 | Cybersecurity risk framework |
| CSA CCM | ~50 | Cloud security controls |
| GDPR | ~50 | EU data protection |

**Pipeline (9 stages):**

```
┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Collect  │──►│ Normalize│──►│ Evaluate │──►│ Risk     │──►│ Attack   │
│ (64     │   │ Evidence │   │ (113    │   │ Score    │   │ Paths    │
│ collect.)│   │ (UUID5)  │   │ checks) │   │ (sev ×  │   │ Analysis │
└─────────┘   └──────────┘   └──────────┘   │ exploit ×│   └────┬─────┘
                                              │ blast)  │        │
                                              └─────────┘        ▼
┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Reports │◄──│ AI Fix   │◄──│ Suppress │◄──│ Priority │◄──│          │
│ (8      │   │ Recs     │   │ (known   │   │ Rank     │        │
│ formats)│   │ (GPT)    │   │ except.) │   │ (ROI)    │        │
└─────────┘   └──────────┘   └──────────┘   └──────────┘        │
```

**Stage details:**

### Stage 1: Collection (64 collectors)
Collectors run asynchronously in batches (4 Azure + 3 Entra concurrent). Each collector calls Azure ARM APIs or Microsoft Graph using the user's delegated tokens.

**Azure collectors (49):** resources, RBAC, policy, diagnostics, activity logs, security, network, Defender, Sentinel, compute, monitoring, AI services, storage, databases, AKS, containers, DNS, Front Door, messaging, Redis, Purview, API Management, and more.

**Entra collectors (13):** users, applications, conditional access, roles, identity protection, governance, audit logs, security policies, risk policies, tenant config, workload identity, AI identity.

### Stage 2: Normalization
Raw evidence from collectors is normalized into a standard schema. Each finding gets a deterministic UUID5 (based on control + resource), ensuring consistent IDs across runs.

### Stage 3: Evaluation (10 domains, 113+ checks)
Evidence is evaluated against framework controls:

| Domain | Example Checks |
|--------|---------------|
| Access | MFA enforcement, password policies, guest access |
| Identity | Privileged roles, PIM usage, stale accounts |
| Data Protection | Encryption at rest, TLS versions, key rotation |
| Logging | Diagnostic settings, audit log retention |
| Network | NSG rules, private endpoints, WAF configuration |
| Governance | Policy compliance, resource locks, tagging |
| Incident Response | Alert rules, automation, playbooks |
| Change Management | Update management, deployment safeguards |
| Business Continuity | Backup policies, geo-redundancy, DR plans |
| Asset Management | Resource inventory, lifecycle, classification |

### Stage 4: Risk Scoring
Each finding is scored: `severity × exploitability × blast_radius`. This produces a weighted risk score rather than a simple pass/fail.

### Stage 5: Attack Path Analysis
Identifies chains of related findings that together create exploitable paths. Example: "Overprivileged service principal + No conditional access + Public storage = Data exfiltration path."

### Stage 6: Priority Ranking
Findings are ranked by ROI: `risk / √effort`. This tells you what to fix first for maximum security improvement with minimum effort.

### Stage 7: Suppressions
Known exceptions and accepted risks are loaded and applied, removing acknowledged findings from the active results.

### Stage 8: AI Fix Recommendations
GPT generates tenant-specific remediation scripts (Azure CLI, PowerShell) for each finding, batched for efficiency.

### Stage 9: Report Generation
Multi-format output: HTML, PDF, Excel, JSON, OSCAL, SARIF, Markdown + ZIP bundle. See [Report Lifecycle](03-report-lifecycle.md).

---

## 2. Risk Analysis

**What it evaluates:** Security risk gaps across 5 categories.

| Category | What It Checks |
|----------|---------------|
| Identity | Privileged access, MFA gaps, stale credentials |
| Network | Open NSGs, missing WAF, public endpoints |
| Defender | Defender plan coverage, alert configuration |
| Config Drift | Deviation from security baselines |
| Insider Risk | Overprivileged users, unusual access patterns |

**Output:** HTML report + PDF + Excel + JSON

---

## 3. Data Security

**What it evaluates:** Data-layer protections across 30+ categories.

Key evaluation areas:
- Storage account encryption and access controls
- Database security (SQL, Cosmos DB, PostgreSQL, MySQL)
- Key Vault configuration and key rotation
- Private endpoint coverage
- Data classification and labeling (Purview)
- M365 DLP policies
- Backup and disaster recovery
- Container data security
- AI service data protection
- Messaging security (Service Bus, Event Hub)

**Output:** HTML report + PDF + Excel + Executive Brief + JSON

---

## 4. Copilot Readiness

**What it evaluates:** Whether your tenant is ready for Microsoft 365 Copilot Premium.

| Module | What It Checks |
|--------|---------------|
| Oversharing | Files accessible by too many users |
| Labels | Sensitivity label adoption and coverage |
| DLP | Data Loss Prevention policy completeness |
| Restricted Search | SharePoint search scope configuration |
| Access Governance | Access reviews, lifecycle workflows |
| Content Lifecycle | Retention and disposition policies |
| Audit Monitoring | Copilot audit log configuration |
| Copilot Security | Copilot-specific security settings |
| Zero Trust | Zero Trust alignment score |
| Shadow AI | Unauthorized AI tool usage detection |

**Output:** HTML report + PDF + Excel + JSON

---

## 5. AI Agent Security

**What it evaluates:** Security posture of AI agents across 3 platforms.

### Platform A: Copilot Studio
Auth, data connectors, logging, channels, knowledge sources, generative AI, governance, DLP, environment isolation, Dataverse security.

### Platform B: Microsoft Foundry
Network isolation, identity, content safety, model deployments, governance, compute security, datastores, endpoints, registry, connections, serverless, diagnostics, prompt shields, model catalog, data exfiltration prevention, agent identity, MCP tools, guardrails, hosted agents, observability, lifecycle.

### Platform C: Custom Agents
API security, data residency, content leakage prevention.

**Additional evaluations:**
- **Entra AI Identity:** Service principals, conditional access, consent, workload identity
- **AI Infrastructure:** Diagnostics, model governance, threat protection
- **Agent Orchestration:** Defender coverage, policy compliance, agent communication

**Output:** HTML report + PDF + Excel + JSON

---

## 6. RBAC Report

**What it evaluates:** The complete Role-Based Access Control hierarchy of your Azure environment.

```
Management Groups
  └── Subscriptions
       └── Resource Groups
            └── Resources
                 └── Role Assignments
                      ├── Users
                      ├── Groups (expanded to members)
                      └── Service Principals

+ PIM Eligibility
+ Risk Analysis (overprivileged accounts)
```

**Output:** Interactive HTML report with expandable tree, filterable tables

---

## 7. Cloud Explorer

**What it does:** Natural language queries against your Azure and Entra ID environment.

Examples:
- "Show me all storage accounts without private endpoints"
- "List users with Global Administrator role"
- "Find VMs with public IP addresses"

Uses Azure Resource Graph (50+ query templates) and Microsoft Graph for Entra data.

**Output:** Structured query results displayed inline in chat

---

## Web App Options and Controls

Each assessment HTML page provides these user controls:

### Sidebar Navigation
- Assessment type selection (icons for each engine)
- Framework selection checkboxes (for PostureIQ)
- Quick-start chips (pre-defined prompts)
- Session history list

### Chat Interface
- Message input with send button
- Streaming response display
- Tool execution progress indicators
- Report download table (HTML/PDF/Excel for each framework)
- Follow-up suggestion chips

### Session Controls
- **New Session:** Clears chat, resets conversation ID
- **Stop:** Aborts in-progress assessment
- **Theme Toggle:** Light/dark mode
- **Session Restore:** Previous sessions restored from localStorage

### PostureIQ-Specific Options
When running PostureIQ, you can:
1. **Select frameworks** in the sidebar (e.g., just FedRAMP, or all 11)
2. **Type a custom prompt** (e.g., "Run assessment for FedRAMP and CIS only")
3. **Use quick-start chips** (pre-defined assessment prompts)

The system passes your framework selection to the `run_postureiq_assessment` tool's `frameworks` parameter.

---

## Behind the Scenes: What Happens When You Click "Run Assessment"

### Sequence Diagram

```
Browser                    API (FastAPI)             Azure OpenAI            Tool Engine
  │                           │                         │                       │
  │  POST /chat               │                         │                       │
  │  {message, tokens, page}  │                         │                       │
  │──────────────────────────►│                         │                       │
  │                           │                         │                       │
  │                           │  Validate tokens        │                       │
  │                           │  Create credentials     │                       │
  │                           │                         │                       │
  │                           │  chat.completions       │                       │
  │                           │  (messages + tools)     │                       │
  │                           │────────────────────────►│                       │
  │                           │                         │                       │
  │                           │  tool_call:             │                       │
  │                           │  run_postureiq(FedRAMP) │                       │
  │                           │◄────────────────────────│                       │
  │                           │                         │                       │
  │  SSE: {tool: "running"}   │                         │                       │
  │◄──────────────────────────│                         │                       │
  │                           │                         │                       │
  │                           │  Execute tool                                   │
  │                           │────────────────────────────────────────────────►│
  │                           │                                                 │
  │                           │                         Collect (64 collectors) │
  │                           │                         Evaluate (113 checks)   │
  │                           │                         Score + Attack Paths    │
  │                           │                         Generate reports        │
  │                           │                         Upload to blob          │
  │                           │                                                 │
  │                           │  Results + report URLs                          │
  │                           │◄────────────────────────────────────────────────│
  │                           │                         │                       │
  │  SSE: {tool: "done"}      │                         │                       │
  │◄──────────────────────────│                         │                       │
  │                           │                         │                       │
  │  SSE: {report: url}       │  Format summary         │                       │
  │◄──────────────────────────│────────────────────────►│                       │
  │                           │◄────────────────────────│                       │
  │  SSE: {response: "..."}   │                         │                       │
  │◄──────────────────────────│                         │                       │
  │                           │                         │                       │
  │  Render chat + reports    │                         │                       │
  │                           │                         │                       │
```

### Timeline for a Typical PostureIQ Run

| Phase | Duration | What Happens |
|-------|----------|-------------|
| Token validation | ~50ms | JWT decode, credential creation |
| LLM tool selection | ~2-5s | GPT decides which tool to call |
| Permission preflight | ~3-5s | Checks if tokens have required permissions |
| Evidence collection | ~60-180s | 64 collectors run in parallel batches |
| Evaluation | ~5-10s | 113 checks against framework controls |
| Risk scoring | ~2-3s | Severity × exploitability × blast radius |
| Attack paths | ~3-5s | Multi-hop path analysis |
| Priority ranking | ~1s | ROI calculation |
| AI fix recommendations | ~15-30s | GPT batch generates remediation scripts |
| Report generation | ~10-20s | HTML + PDF + Excel + JSON + ZIP |
| Blob upload | ~5-10s | Upload to Azure Storage |
| LLM summary | ~5-10s | GPT writes executive summary |
| **Total** | **~2-5 minutes** | End-to-end |

---

**Next:** [Report Lifecycle →](03-report-lifecycle.md)
