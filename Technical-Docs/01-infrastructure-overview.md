# Infrastructure Overview

> How PostureIQ is built, deployed, and runs in Azure.

**Navigation:** [Index](index-of-tech-docs.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## What Is PostureIQ?

PostureIQ is an AI-powered security posture assessment platform. It connects to your Microsoft Azure and Entra ID environment, collects security evidence from 64 data collectors, evaluates that evidence against 11 compliance frameworks (525 controls), and produces risk-scored reports with attack path analysis and AI-generated remediation recommendations.

It runs as a single containerised application on Azure Container Apps, backed by Azure OpenAI for intelligent analysis.

---

## Azure Resources (14 Components)

The following diagram shows how the resources relate to each other:

```
┌───────────────────────────────────────────────────────────────────┐
│                        ESIQNew-RG (Resource Group)                │
│                                                                   │
│  ┌─────────────────┐    ┌─────────────────┐                      │
│  │  ESIQNew-AI      │    │  ESIQNew-project │                     │
│  │  (Foundry/       │◄───│  (Foundry        │                     │
│  │   AIServices)    │    │   Project)       │                     │
│  │                  │    └─────────────────┘                      │
│  │  ┌──────────┐   │                                             │
│  │  │ gpt-4.1  │   │   ┌──────────────────┐                     │
│  │  │ gpt-5.1  │   │   │  esiqnewacr       │                    │
│  │  └──────────┘   │   │  (Container       │                    │
│  └─────────────────┘   │   Registry)       │                    │
│                         └────────┬─────────┘                     │
│                                  │ pulls image                   │
│  ┌──────────────────┐   ┌───────▼──────────┐                    │
│  │  ESIQNew-env      │◄──│  esiqnew-agent   │                    │
│  │  (Container Apps  │   │  (Container App) │                    │
│  │   Environment)    │   │  1 CPU, 2 GiB    │                    │
│  └──────────────────┘   │  Port 8088        │                    │
│                          └──┬───┬───┬───────┘                    │
│                  uses       │   │   │   uploads reports           │
│         ┌───────────────────┘   │   └────────┐                   │
│         ▼                       ▼            ▼                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐       │
│  │ ESIQNew-     │  │ ESIQNew-kv   │  │ esiqnewstorage   │       │
│  │ identity     │  │ (Key Vault)  │  │ (Storage Account)│       │
│  │ (Managed ID) │  └──────────────┘  │  └─ reports (blob)│       │
│  └──────────────┘                    └──────────────────┘       │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐                      │
│  │ ESIQNew-law      │  │ ESIQNew-         │                      │
│  │ (Log Analytics)  │◄─│ appinsights      │                      │
│  └──────────────────┘  │ (App Insights)   │                      │
│                         └──────────────────┘                      │
└───────────────────────────────────────────────────────────────────┘
```

### Resource Details

| # | Resource | Name | SKU / Config | Purpose |
|---|----------|------|-------------|---------|
| 1 | Resource Group | `ESIQNew-RG` | swedencentral | Container for all resources |
| 2 | Foundry Resource | `ESIQNew-AI` | AIServices, S0 | Azure OpenAI + AI Services host |
| 3 | Foundry Project | `ESIQNew-project` | Child of ESIQNew-AI | Project container for models and agents |
| 4 | Primary Model | `gpt-4.1` | Standard, 30K TPM | Main LLM for agent reasoning |
| 5 | Fallback Model | `gpt-5.1` | Standard, 30K TPM | Used when primary fails or context overflows |
| 6 | Storage Account | `esiqnewstorage` | Standard_LRS | Report blob storage (container: `reports`) |
| 7 | Key Vault | `ESIQNew-kv` | Standard, RBAC auth | Secrets management |
| 8 | Log Analytics | `ESIQNew-law` | PerGB2018 | Central log collection |
| 9 | App Insights | `ESIQNew-appinsights` | Workspace-based | Application performance monitoring |
| 10 | Container Registry | `esiqnewacr` | Basic | Docker image storage |
| 11 | Managed Identity | `ESIQNew-identity` | User-assigned | Service authentication to Azure |
| 12 | Container Apps Env | `ESIQNew-env` | Consumption, northeurope | Hosting environment for container |
| 13 | Container App | `esiqnew-agent` | 1 vCPU, 2 GiB, port 8088 | The running application |
| 14 | Foundry Agent | `EnterpriseSecurityIQ` | Assistants API | Registered AI agent with 14 tools |

---

## RBAC Role Assignments

The managed identity (`ESIQNew-identity`) is assigned these roles so the container can access Azure resources:

| Role | Scope | Why |
|------|-------|-----|
| `AcrPull` | Container Registry | Pull Docker images |
| `Reader` | Subscription | Read Azure resource metadata |
| `Security Reader` | Subscription | Read Defender, Security Center data |
| `Cognitive Services OpenAI User` | AI Services | Call Azure OpenAI models |
| `Azure AI Developer` | AI Services | Register and manage Foundry agents |
| `Storage Blob Data Contributor` | Storage Account | Upload and download report files |

Additionally, 8 Microsoft Graph API permissions are granted (application-level):

| Permission | Why |
|------------|-----|
| `Directory.Read.All` | Read users, groups, org structure |
| `Policy.Read.All` | Read conditional access, auth policies |
| `RoleManagement.Read.All` | Read directory role assignments |
| `User.Read.All` | Read user profiles and properties |
| `AuditLog.Read.All` | Read audit log entries |
| `UserAuthenticationMethod.Read.All` | Check MFA registration status |
| `IdentityRiskyUser.Read.All` | Read identity risk detections |
| `Application.Read.All` | Read app registrations and service principals |

---

## Container App Configuration

The container app runs with these settings:

```yaml
Image:      esiqnewacr.azurecr.io/esiqnew-agent:<tag>
Port:       8088
CPU:        1 vCPU
Memory:     2 GiB
Replicas:   min=1, max=1
Ingress:    External, HTTPS only
FQDN:       esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io
```

### Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `AZURE_OPENAI_ENDPOINT` | `https://esiqnew-ai.cognitiveservices.azure.com/` | AI Services endpoint |
| `AZURE_OPENAI_API_VERSION` | `2025-01-01-preview` | API version |
| `PRIMARY_MODEL` | `gpt-4.1` | Primary LLM model |
| `FALLBACK_MODEL` | `gpt-5.1` | Fallback LLM model |
| `AZURE_CLIENT_ID` | `d5d10273-...` | Managed identity client ID |
| `AZURE_TENANT_ID` | `4a3eb5f4-...` | Azure AD tenant ID |
| `FOUNDRY_PROJECT_ENDPOINT` | `https://esiqnew-ai.services.ai.azure.com/...` | Foundry project endpoint |
| `REPORT_STORAGE_ACCOUNT` | `esiqnewstorage` | Blob storage account name |
| `REPORT_STORAGE_CONTAINER` | `reports` | Blob container name |

---

## Dockerfile

The Docker image is built from `AIAgent/Dockerfile`:

```
Step 1: Start from Python 3.12 slim (cached in ACR)
Step 2: Install system dependencies (Chromium for PDF generation)
Step 3: Install Playwright browsers
Step 4: Copy requirements.txt and install Python packages (40+ Azure SDKs)
Step 5: Copy application code (AIAgent/app/, AIAgent/main.py)
Step 6: Copy webapp files (all HTML/JS/CSS)
Step 7: Create non-root user (appuser)
Step 8: Set healthcheck (GET /health)
Step 9: CMD: uvicorn app.api:app --host 0.0.0.0 --port 8088
```

Key details:
- **Playwright Chromium** is installed inside the container for server-side HTML→PDF conversion
- Runs as non-root user `appuser` for security
- Working directory: `/agent`
- Reports are written to `/agent/output/` inside the container

---

## Build and Deploy Process

### Full Deployment (First Time)

The script `Infra-Foundary-New/deploy.ps1` performs a 16-step idempotent deployment:

```
Step  1/16: Create Resource Group
Step  2/16: Create Foundry Resource (AIServices)
Step  3/16: Create Foundry Project
Step  4/16: Deploy Primary Model (gpt-4.1)
Step  5/16: Deploy Fallback Model (gpt-5.1)
Step  6/16: Create Storage Account + "reports" container
Step  7/16: Create Key Vault
Step  8/16: Create Log Analytics Workspace
Step  9/16: Create Application Insights
Step 10/16: Create Container Registry
Step 11/16: Create User-Assigned Managed Identity
Step 12/16: Assign RBAC Roles (6 Azure + 8 Graph permissions)
Step 13/16: Create Container Apps Environment
Step 14/16: Build image + Create Container App
Step 15/16: Create Entra App Registration (SPA)
Step 16/16: Patch webapp with MSAL config, rebuild, update container
```

Each step checks if the resource already exists before creating, making it safe to re-run.

### Quick Redeployment (Code Changes Only)

The script `Infra-Foundary-New/redeploy-image.ps1` performs a 3-step update:

```
Step 1/3: Build new image via ACR Tasks
           az acr build --registry esiqnewacr --image esiqnew-agent:<tag> ...
Step 2/3: Update container app image reference
           az containerapp update --image esiqnewacr.azurecr.io/esiqnew-agent:<tag>
Step 3/3: Restart active revision
           az containerapp revision restart ...
```

### Manual Build Commands

```powershell
# 1. Prepare build context
if (Test-Path C:\Temp\esiq-ctx) { Remove-Item -Recurse -Force C:\Temp\esiq-ctx }
New-Item -ItemType Directory -Path C:\Temp\esiq-ctx\AIAgent -Force
New-Item -ItemType Directory -Path C:\Temp\esiq-ctx\webapp -Force
Copy-Item -Recurse -Force "AIAgent\app" C:\Temp\esiq-ctx\AIAgent\
Copy-Item -Force "AIAgent\main.py" C:\Temp\esiq-ctx\AIAgent\
Copy-Item -Force "AIAgent\requirements.txt" C:\Temp\esiq-ctx\AIAgent\
Copy-Item -Force "AIAgent\Dockerfile" C:\Temp\esiq-ctx\AIAgent\
Copy-Item -Recurse -Force "webapp\*" C:\Temp\esiq-ctx\webapp\

# 2. Build image in ACR
az acr build --registry esiqnewacr --image esiqnew-agent:v94 `
  --file AIAgent/Dockerfile C:\Temp\esiq-ctx `
  --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss') --no-logs

# 3. Deploy new image
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG `
  --image esiqnewacr.azurecr.io/esiqnew-agent:v94 -o table
```

---

## Network Architecture

```
Internet ──► Azure Container Apps (HTTPS, port 443)
              │
              ├── Envoy proxy (TLS termination)
              │     │
              │     └── Container: esiqnew-agent (port 8088)
              │           │
              │           ├──► Azure OpenAI (HTTPS)
              │           ├──► Azure Blob Storage (HTTPS)
              │           ├──► Microsoft Graph API (HTTPS)
              │           └──► Azure Resource Manager (HTTPS)
              │
              └── CORS: teams.microsoft.com, *.office.com,
                        *.cloud.microsoft, *.microsoft365.com
```

- External ingress with HTTPS only
- No VNet integration (public network)
- CORS restricted to Microsoft Teams and Office domains
- Content Security Policy allows Teams iframe embedding

---

## Storage Architecture

Reports are stored in two places:

1. **Local filesystem** (`/agent/output/` inside the container) — fast, ephemeral
2. **Azure Blob Storage** (`esiqnewstorage/reports`) — persistent across restarts

```
Assessment completes
    │
    ├── Write to /agent/output/20260422_023002_PM/FedRAMP/
    │     ├── fedramp-compliance-report.html
    │     ├── fedramp-compliance-report.pdf
    │     ├── fedramp-compliance-report.xlsx
    │     └── fedramp-compliance.json
    │
    └── Upload to blob storage (same relative path)
          └── reports/20260422_023002_PM/FedRAMP/...

User requests report:
    │
    ├── Check local filesystem first (fast)
    │     └── Found? → Serve directly
    │
    └── Not found? → Download from blob storage → Serve
          └── Not in blob either? → 404 "Report not found"
```

---

**Next:** [Assessment Guide →](02-assessment-guide.md)
