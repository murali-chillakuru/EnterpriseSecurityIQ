# PostureIQ Technical Documentation

> Complete technical documentation for the EnterpriseSecurityIQ (PostureIQ) platform.

---

## Documents

| # | Document | Description |
|---|----------|-------------|
| 1 | [Infrastructure Overview](01-infrastructure-overview.md) | Azure resources, RBAC, container config, build/deploy process, network and storage architecture |
| 2 | [Assessment Guide](02-assessment-guide.md) | All 8 assessment engines, evaluation pipeline, collectors, scoring, behind-the-scenes sequence |
| 3 | [Report Lifecycle](03-report-lifecycle.md) | Report formats (HTML/PDF/Excel/JSON/OSCAL/SARIF), generation pipeline, storage flow, historical tracking |
| 4 | [Manual Setup Guide](04-manual-setup-guide.md) | Step-by-step instructions to manually recreate the entire infrastructure from scratch |
| 5 | [Authentication Flow](05-authentication-flow.md) | MSAL.js, Teams SSO (NAA), managed identity, token flow diagrams |
| 6 | [API Reference](06-api-reference.md) | All HTTP endpoints, SSE streaming protocol, CORS, request/response formats |
| 7 | [Teams Integration](07-teams-integration.md) | Teams manifest, NAA, theme sync, iframe security, installation steps |
| 8 | [Troubleshooting](08-troubleshooting.md) | Common issues with authentication, storage, containers, assessments, and deployment |

---

## Quick Links

### For Beginners
- **"What is PostureIQ?"** → [Infrastructure Overview](01-infrastructure-overview.md#what-is-postureiq)
- **"How do I deploy this?"** → [Manual Setup Guide](04-manual-setup-guide.md)
- **"What assessments can I run?"** → [Assessment Guide](02-assessment-guide.md#assessment-types-overview)
- **"Something is broken"** → [Troubleshooting](08-troubleshooting.md)

### For Developers
- **API endpoints and SSE events** → [API Reference](06-api-reference.md)
- **How authentication works** → [Authentication Flow](05-authentication-flow.md)
- **Report generation code** → [Report Lifecycle](03-report-lifecycle.md#report-modules)
- **Teams app setup** → [Teams Integration](07-teams-integration.md)

### For Operators
- **Full deployment script** → [Manual Setup Guide](04-manual-setup-guide.md)
- **Quick redeployment** → [Manual Setup Guide](04-manual-setup-guide.md#quick-redeployment-code-changes-only)
- **Diagnostic commands** → [Troubleshooting](08-troubleshooting.md#diagnostic-commands-quick-reference)
- **RBAC roles and Graph permissions** → [Infrastructure Overview](01-infrastructure-overview.md#rbac-role-assignments)

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Access Points                          │
│                                                                     │
│   Browser (SPA)          Teams Tab           Foundry Agent          │
│   MSAL.js popup         Teams SSO (NAA)     Managed Identity        │
│        │                     │                    │                  │
│        └─────────┬───────────┘                    │                  │
│                  ▼                                 │                  │
│   ┌──────────────────────────┐                    │                  │
│   │  Container App           │◄───────────────────┘                  │
│   │  (FastAPI + Uvicorn)     │                                       │
│   │  Port 8088               │                                       │
│   │                          │                                       │
│   │  ┌────────────────────┐  │                                       │
│   │  │  Agent (14 tools)  │  │                                       │
│   │  │  8 assessments     │  │                                       │
│   │  │  47 report modules │  │                                       │
│   │  │  64 collectors     │  │                                       │
│   │  └────────────────────┘  │                                       │
│   └──────┬──────┬─────┬──────┘                                       │
│          │      │     │                                              │
│    ┌─────┘      │     └──────┐                                       │
│    ▼            ▼            ▼                                       │
│  Azure       Azure        Azure                                     │
│  OpenAI      Blob         Graph +                                   │
│  (GPT)       Storage      ARM APIs                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Azure resources | 14 |
| Assessment engines | 8 |
| Agent tools | 14 |
| Data collectors | 64 (49 Azure + 13 Entra + 2 general) |
| Evaluation checks | 113+ |
| Compliance frameworks | 11 |
| Compliance controls | 525 |
| Report modules | 47 (27 generic + 20 PostureIQ) |
| Report formats | 8 (HTML, PDF, Excel, JSON, OSCAL, SARIF, Markdown, ZIP) |
| API routes | 7 |
| RBAC roles | 6 Azure + 8 Graph permissions |
