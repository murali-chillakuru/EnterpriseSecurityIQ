# Assessment Engines

> All 7 standalone assessment engines — capabilities, categories, and usage.

PostureIQ includes 7 standalone engines that can run independently or through the orchestrator. Each engine collects relevant evidence, performs specialized analysis, and produces a focused report.

## 1. Security Compliance Assessment

The core engine that runs the full multi-framework compliance assessment.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `run_assessment` |
| **CLI Script** | `run_assessment.py` |
| **Scope** | All 10 evaluation domains, 68 collectors |
| **Output** | Full compliance report across selected frameworks |

**What it does:**
- Discovers all Azure subscriptions and Entra ID configuration
- Runs 68 collectors concurrently to gather 218 evidence types
- Evaluates against 113 check functions across 10 domains
- Maps findings to selected compliance frameworks (up to 11, 525 controls)
- Generates reports in up to 8 formats

**Usage:**
```bash
python run_assessment.py --tenant <id> --framework NIST-800-53 CIS FedRAMP
```

## 2. Risk Assessment

Security risk gap analysis focused on identifying the highest-impact vulnerabilities.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `analyze_risk` |
| **CLI Script** | `run_risk_analysis.py` |
| **Categories** | 4: Identity, Network, Defender, Configuration |
| **Output** | Risk gap report with severity ranking |

**What it does:**
- Analyzes identity risks (MFA gaps, stale accounts, risky users, privilege escalation paths)
- Evaluates network exposure (open NSGs, public storage, missing firewalls)
- Checks Defender coverage (missing plans, disabled auto-provisioning)
- Reviews configuration hygiene (unpatched resources, missing encryption, policy drift)

**Usage:**
```bash
python run_risk_analysis.py --tenant <id>
```

## 3. Data Security Assessment

Data-layer posture assessment covering storage, databases, encryption, and classification.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `assess_data_security` |
| **CLI Script** | `run_data_security.py` |
| **Categories** | 12 |
| **Output** | Data security assessment report |

**What it does:**
- Storage exposure analysis (public containers, blob access levels, SAS tokens)
- Database security (SQL audit, TDE, firewall rules, Cosmos DB settings)
- Encryption posture (in-transit, at-rest, Key Vault key/secret/cert expiry)
- Data classification (Purview labels, sensitivity label coverage)
- Messaging security (Service Bus, Event Hub configurations)
- Cache security (Redis access, TLS settings)

**Usage:**
```bash
python run_data_security.py --tenant <id>
```

## 4. RBAC Assessment

Interactive RBAC hierarchy visualization with risk analysis and PIM integration.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `generate_rbac_report` |
| **CLI Script** | `run_rbac_report.py` |
| **Output** | Interactive HTML tree with expandable hierarchy |

**What it does:**
- Builds full RBAC hierarchy: Management Groups → Subscriptions → Resource Groups
- Shows all role assignments with scope, principal, and role definition
- Expands group memberships to show effective access
- Identifies PIM-eligible vs. active assignments
- Flags high-risk assignments (Owner at subscription scope, custom roles with wide permissions)
- Produces an interactive HTML report with collapsible tree navigation

**Usage:**
```bash
python run_rbac_report.py --tenant <id>
```

## 5. Copilot Readiness Assessment

M365 Copilot readiness assessment covering data governance, oversharing, and security controls.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `assess_copilot_readiness` |
| **CLI Script** | `run_copilot_readiness.py` |
| **Categories** | 9+ |
| **Output** | Copilot readiness report with recommendations |

**What it does:**
- Oversharing analysis (broad SharePoint/OneDrive access, everyone-except-external-users groups)
- Sensitivity label coverage (labeled vs. unlabeled content, label enforcement policies)
- Data Loss Prevention (DLP policies, coverage gaps, endpoint DLP status)
- Restricted SharePoint search (site-level search scope configuration)
- Access governance (access reviews, entitlement management, guest policies)
- Conditional access readiness (Copilot-specific CA policies)
- Information barriers (segment configuration, policy coverage)
- Audit and compliance (audit logging, retention policies, eDiscovery readiness)

**Usage:**
```bash
python run_copilot_readiness.py --tenant <id>
```

## 6. AI Agent Security Assessment

Security posture assessment for AI agent platforms including Copilot Studio, Foundry, and custom agents.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `assess_ai_agent_security` |
| **CLI Script** | `run_ai_agent_security.py` |
| **Platforms** | 6 |
| **Assessment Areas** | 23+ |
| **Output** | AI agent security report |

**What it does:**
- Copilot Studio security (bot authentication, DLP connector policies, tenant isolation)
- Azure AI Foundry (model deployment security, endpoint authentication, network isolation)
- Custom agent security (API authentication, rate limiting, input validation)
- AI model governance (model registry access, deployment approvals, version control)
- Data handling (training data protection, inference data logging, PII handling)
- Responsible AI (content filtering, grounding, prompt injection protection)

**Usage:**
```bash
python run_ai_agent_security.py --tenant <id>
```

## 7. PostureIQ Assessment

Risk-weighted posture assessment with attack path analysis, priority ranking, and AI-generated fix recommendations.

| Attribute | Value |
|-----------|-------|
| **Agent Tool** | `run_postureiq_assessment` |
| **Output** | PostureIQ report with priority ranking and AI fixes |

**What it does:**
- Combines findings from the compliance assessment engine
- Applies risk-weighted scoring based on severity, exploitability, and blast radius
- Identifies attack paths (chains of findings that together create exploitable paths)
- Ranks findings by priority: what to fix first for maximum risk reduction
- Generates AI-powered remediation recommendations with step-by-step instructions

## Supporting Engines

In addition to the 7 assessment engines, PostureIQ includes supporting modules:

| Engine | Purpose |
|--------|---------|
| **Cloud Explorer** | Live Azure Resource Graph (KQL) and MS Graph queries with natural language support |
| **Data Residency Engine** | Data residency compliance checks (5 checks) |
| **Remediation Engine** | Automated remediation plan generation |
| **Continuous Monitor** | Scheduled re-assessments with drift detection |
| **SIEM Integration** | Export to Sentinel, Splunk, or generic webhooks |
| **Operational Integrations** | ServiceNow, Jira, and Azure DevOps connectors |
