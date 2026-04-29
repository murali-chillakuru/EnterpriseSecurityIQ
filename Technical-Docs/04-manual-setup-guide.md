# Manual Setup Guide

> Step-by-step instructions to manually recreate the entire PostureIQ infrastructure from scratch.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · **Manual Setup** · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## Prerequisites

Before you begin, ensure you have:

| Requirement | Version / Details |
|-------------|------------------|
| Azure CLI | 2.67+ (`az --version`) |
| Azure Subscription | With permissions to create resources |
| Global Administrator | Required for Graph API permissions (Step 12) |
| PowerShell | 7+ (or Windows PowerShell 5.1) |
| Git | For cloning the repository |

### Verify Azure CLI

```powershell
az --version
az login
az account set --subscription "AI"   # Replace with your subscription name
```

---

## Variables

Set these variables in your PowerShell session. Change the values to match your environment:

```powershell
$BaseName              = "ESIQNew"
$Location              = "swedencentral"        # AI Services region
$ContainerAppsLocation = "northeurope"          # Container Apps region
$SubscriptionName      = "AI"
$PrimaryModel          = "gpt-4.1"
$FallbackModel         = "gpt-5.1"
$ModelSku              = "Standard"
$ModelCapacity         = 30                     # 30K TPM

# Derived names (do not change these unless you change BaseName)
$RG           = "$BaseName-RG"
$AIName       = "$BaseName-AI"
$CustomDomain = $AIName.ToLower()
$ProjectName  = "$BaseName-project"
$StorageName  = "$($BaseName.ToLower())storage"
$KVName       = "$BaseName-kv"
$AppInsights  = "$BaseName-appinsights"
$LAWName      = "$BaseName-law"
$ACRName      = "$($BaseName.ToLower())acr"
$IDName       = "$BaseName-identity"
$EnvName      = "$BaseName-env"
$AppName      = "$($BaseName.ToLower())-agent"

$SubId    = az account show --query "id" -o tsv
$TenantId = az account show --query "tenantId" -o tsv
```

---

## Step 1: Create Resource Group

```powershell
az group create --name $RG --location $Location -o none
```

**What this does:** Creates a container that holds all your resources. All subsequent resources are placed inside this group.

**Verify:**
```powershell
az group show --name $RG --query "{name:name, location:location}" -o table
```

---

## Step 2: Create Foundry Resource (AI Services)

```powershell
# Create the AI Services resource
az cognitiveservices account create `
    --name $AIName --resource-group $RG `
    --kind "AIServices" --sku "S0" `
    --location $Location --yes -o none

# Set custom domain (required for project management)
az cognitiveservices account update `
    --name $AIName --resource-group $RG `
    --custom-domain $CustomDomain -o none

# Enable project management via REST API
$aiUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.CognitiveServices/accounts/${AIName}?api-version=2025-04-01-preview"
$bodyFile = [System.IO.Path]::GetTempPath() + "esiq-allow-pm.json"
[System.IO.File]::WriteAllText($bodyFile, '{"properties":{"allowProjectManagement":true}}', [System.Text.Encoding]::UTF8)
az rest --method PATCH --uri $aiUri --body "@$bodyFile" -o none
Remove-Item -Force $bodyFile
```

**What this does:** Creates an Azure AI Services resource with a custom domain name. The `allowProjectManagement` setting enables the new Foundry project model (visible at ai.azure.com).

**Wait for provisioning:**
```powershell
do {
    $state = az cognitiveservices account show --name $AIName --resource-group $RG `
        --query "properties.provisioningState" -o tsv
    if ($state -ne "Succeeded") { Start-Sleep -Seconds 5 }
} while ($state -ne "Succeeded")

# Save endpoint for later
$AIEndpoint = az cognitiveservices account show --name $AIName --resource-group $RG `
    --query "properties.endpoint" -o tsv
$AIId = az cognitiveservices account show --name $AIName --resource-group $RG `
    --query "id" -o tsv
```

---

## Step 3: Create Foundry Project

```powershell
$ApiVersion = "2025-06-01"
$projUri = "https://management.azure.com${AIId}/projects/${ProjectName}?api-version=$ApiVersion"

$projBodyFile = [System.IO.Path]::GetTempPath() + "esiq-project.json"
$projBody = @"
{"location":"$Location","identity":{"type":"SystemAssigned"},"properties":{}}
"@
[System.IO.File]::WriteAllText($projBodyFile, $projBody, [System.Text.Encoding]::UTF8)
az rest --method PUT --uri $projUri --body "@$projBodyFile" -o none
Remove-Item -Force $projBodyFile
```

**What this does:** Creates a Foundry Project as a child resource of the AI Services account. This project is visible in the ai.azure.com portal under the "New Foundry" toggle.

**Wait and save endpoint:**
```powershell
do {
    $state = az rest --method GET --uri $projUri `
        --query "properties.provisioningState" -o tsv 2>$null
    if ($state -ne "Succeeded") { Start-Sleep -Seconds 5 }
} while ($state -ne "Succeeded")

$ProjectEndpoint = az rest --method GET --uri $projUri `
    --query "properties.endpoints.\"AI Foundry API\"" -o tsv
```

---

## Step 4: Deploy Primary Model (gpt-4.1)

```powershell
az cognitiveservices account deployment create `
    --name $AIName --resource-group $RG `
    --deployment-name $PrimaryModel `
    --model-name $PrimaryModel --model-version "2025-04-14" `
    --model-format "OpenAI" --sku-name $ModelSku --sku-capacity $ModelCapacity -o none
```

**What this does:** Deploys the GPT-4.1 model with 30K tokens per minute (TPM) throughput. This is the primary model used for agent reasoning.

---

## Step 5: Deploy Fallback Model (gpt-5.1)

```powershell
az cognitiveservices account deployment create `
    --name $AIName --resource-group $RG `
    --deployment-name $FallbackModel `
    --model-name $FallbackModel --model-version "2025-11-13" `
    --model-format "OpenAI" --sku-name $ModelSku --sku-capacity $ModelCapacity -o none
```

**What this does:** Deploys GPT-5.1 as a fallback. Used when the primary model fails, is throttled, or when the context window exceeds 4.1's limits.

---

## Step 6: Create Storage Account

```powershell
# Create account
az storage account create `
    --name $StorageName --resource-group $RG `
    --location $Location --sku "Standard_LRS" `
    --kind "StorageV2" --min-tls-version "TLS1_2" -o none

# Create blob container for reports
az storage container create --name "reports" `
    --account-name $StorageName --auth-mode login -o none
```

**What this does:** Creates a storage account with a `reports` blob container. Reports are uploaded here for persistence across container restarts.

**Important notes:**
- `Standard_LRS` = locally redundant (cheapest). Use `Standard_GRS` for geo-redundancy.
- `TLS1_2` enforces minimum TLS version.
- The `reports` container is created via `--auth-mode login` (uses your Azure AD identity, not shared keys).

---

## Step 7: Create Key Vault

```powershell
az keyvault create `
    --name $KVName --resource-group $RG `
    --location $Location `
    --enable-rbac-authorization true `
    --enable-purge-protection true -o none
```

**What this does:** Creates a Key Vault for secrets management with RBAC authorization (no access policies) and purge protection enabled.

---

## Step 8: Create Log Analytics Workspace

```powershell
az monitor log-analytics workspace create `
    --resource-group $RG --workspace-name $LAWName -o none

# Save for later
$LAWId = az monitor log-analytics workspace show `
    --resource-group $RG --workspace-name $LAWName --query "id" -o tsv
$LAWCustomerId = az monitor log-analytics workspace show `
    --resource-group $RG --workspace-name $LAWName --query "customerId" -o tsv
```

**What this does:** Creates a Log Analytics workspace that collects container logs, AI Services logs, and Application Insights telemetry.

---

## Step 9: Create Application Insights

```powershell
az monitor app-insights component create `
    --app $AppInsights --resource-group $RG `
    --location $Location `
    --workspace $LAWId -o none
```

**What this does:** Creates an Application Insights instance linked to the Log Analytics workspace. Provides request tracking, dependency tracing, and performance monitoring.

---

## Step 10: Create Container Registry

```powershell
az acr create --name $ACRName --resource-group $RG --sku "Basic" -o none
```

**What this does:** Creates a Basic-tier container registry to store Docker images. The `Basic` SKU is sufficient for single-image deployments.

Save the registry ID:
```powershell
$ACRId = az acr show --name $ACRName --resource-group $RG --query "id" -o tsv
```

---

## Step 11: Create Managed Identity

```powershell
az identity create --name $IDName --resource-group $RG -o none

# Save IDs for later
$PrincipalId = az identity show --name $IDName --resource-group $RG --query "principalId" -o tsv
$ClientId    = az identity show --name $IDName --resource-group $RG --query "clientId" -o tsv
$IdentityId  = az identity show --name $IDName --resource-group $RG --query "id" -o tsv
```

**What this does:** Creates a user-assigned managed identity. The container app uses this identity to authenticate to all other Azure services (OpenAI, Storage, ACR) without any passwords or keys.

---

## Step 12: Assign RBAC Roles

### Azure RBAC Roles

```powershell
$StorageId = az storage account show --name $StorageName --resource-group $RG --query "id" -o tsv

# ACR Pull — lets the container pull Docker images
az role assignment create --assignee $PrincipalId --role "AcrPull" --scope $ACRId -o none

# Reader — lets the container enumerate Azure resources
az role assignment create --assignee $PrincipalId --role "Reader" `
    --scope "/subscriptions/$SubId" -o none

# Security Reader — lets the container read Defender and Security Center data
az role assignment create --assignee $PrincipalId --role "Security Reader" `
    --scope "/subscriptions/$SubId" -o none

# OpenAI User — lets the container call Azure OpenAI models
az role assignment create --assignee $PrincipalId --role "Cognitive Services OpenAI User" `
    --scope $AIId -o none

# AI Developer — lets the container register/manage Foundry agents
az role assignment create --assignee $PrincipalId --role "Azure AI Developer" `
    --scope $AIId -o none

# Storage Blob Data Contributor — lets the container upload/download reports
az role assignment create --assignee $PrincipalId --role "Storage Blob Data Contributor" `
    --scope $StorageId -o none
```

### Microsoft Graph API Permissions (Requires Global Admin)

```powershell
$GraphAppId = "00000003-0000-0000-c000-000000000000"
$graphSpResp = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles"
$graphSpParsed = ($graphSpResp | Out-String | ConvertFrom-Json).value[0]
$GraphSpId = $graphSpParsed.id
$graphRoles = $graphSpParsed.appRoles

$permissions = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.All",
    "User.Read.All",
    "AuditLog.Read.All",
    "UserAuthenticationMethod.Read.All",
    "IdentityRiskyUser.Read.All",
    "Application.Read.All"
)

foreach ($perm in $permissions) {
    $role = $graphRoles | Where-Object { $_.value -eq $perm }
    if ($role) {
        $body = @{
            principalId = $PrincipalId
            resourceId  = $GraphSpId
            appRoleId   = $role.id
        } | ConvertTo-Json -Compress

        az rest --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
            --body $body --headers "Content-Type=application/json" -o none 2>$null
        Write-Host "Granted $perm"
    }
}
```

**Why each Graph permission is needed:**

| Permission | Assessments That Use It |
|------------|------------------------|
| `Directory.Read.All` | PostureIQ, RBAC, Copilot Readiness |
| `Policy.Read.All` | PostureIQ (conditional access), Copilot Readiness |
| `RoleManagement.Read.All` | RBAC, PostureIQ (privileged roles) |
| `User.Read.All` | PostureIQ (user security), Copilot Readiness |
| `AuditLog.Read.All` | PostureIQ (audit trail), AI Agent Security |
| `UserAuthenticationMethod.Read.All` | PostureIQ (MFA status) |
| `IdentityRiskyUser.Read.All` | Risk Analysis, PostureIQ |
| `Application.Read.All` | AI Agent Security, PostureIQ |

---

## Step 13: Create Container Apps Environment

```powershell
az containerapp env create `
    --name $EnvName --resource-group $RG `
    --logs-workspace-id $LAWCustomerId `
    --location $ContainerAppsLocation -o none
```

**What this does:** Creates a Container Apps environment that hosts your container. This step can take 5–10 minutes.

**Why a different region?** The AI Services region (`swedencentral`) may not support Container Apps. `northeurope` is a common alternative.

---

## Step 14: Build Image and Create Container App

### 14a: Build the Docker Image

```powershell
# Navigate to repository root
cd C:\path\to\EnterpriseSecurityIQ

# Build via ACR Tasks (runs in the cloud, no local Docker needed)
az acr build --registry $ACRName --image "${AppName}:v1" `
    --file "AIAgent/Dockerfile" "." --no-logs
```

### 14b: Create the Container App

```powershell
az containerapp create `
    --name $AppName --resource-group $RG `
    --environment $EnvName `
    --image "${ACRName}.azurecr.io/${AppName}:v1" `
    --registry-server "${ACRName}.azurecr.io" `
    --registry-identity $IdentityId `
    --user-assigned $IdentityId `
    --cpu 1 --memory "2Gi" `
    --min-replicas 0 --max-replicas 3 `
    --target-port 8088 --ingress external `
    --env-vars "AZURE_OPENAI_ENDPOINT=$AIEndpoint" `
               "AZURE_OPENAI_DEPLOYMENT=$PrimaryModel" `
               "AZURE_OPENAI_FALLBACK_DEPLOYMENT=$FallbackModel" `
               "AZURE_OPENAI_API_VERSION=2025-01-01-preview" `
               "FOUNDRY_PROJECT_ENDPOINT=$ProjectEndpoint" `
               "AZURE_CLIENT_ID=$ClientId" `
               "AZURE_TENANT_ID=$TenantId" `
               "REPORT_STORAGE_ACCOUNT=$StorageName" `
               "REPORT_STORAGE_CONTAINER=reports" `
    -o none
```

### 14c: Get the FQDN

```powershell
$FQDN = az containerapp show --name $AppName --resource-group $RG `
    --query "properties.configuration.ingress.fqdn" -o tsv
Write-Host "App URL: https://$FQDN"
```

---

## Step 15: Create Entra App Registration

```powershell
# Create the SPA app registration
$appJson = az ad app create `
    --display-name "$BaseName-Dashboard" `
    --sign-in-audience "AzureADMyOrg" `
    --enable-access-token-issuance true `
    --enable-id-token-issuance true `
    -o json
$AppClientId = ($appJson | ConvertFrom-Json).appId

# Set SPA redirect URIs
az ad app update --id $AppClientId `
    --spa-redirect-uris "http://localhost:8080" "https://$FQDN" -o none
```

**What this does:** Registers a Single Page Application in Entra ID so the web UI can authenticate users and obtain tokens for Microsoft Graph and Azure Resource Manager.

**API Permissions to add manually (Azure Portal):**
1. Go to Entra ID → App Registrations → `ESIQNew-Dashboard`
2. API Permissions → Add a permission
3. Add these **delegated** permissions:
   - Microsoft Graph: `User.Read`, `Directory.Read.All`, `Policy.Read.All`
   - Azure Service Management: `user_impersonation`
4. Click "Grant admin consent"

---

## Step 16: Patch Webapp and Redeploy

```powershell
# Update the webapp HTML files with live MSAL config
$webappFile = "webapp\index.html"
$html = Get-Content $webappFile -Raw -Encoding UTF8
$html = $html.Replace('clientId: "YOUR-CLIENT-ID-HERE"', "clientId: `"$AppClientId`"")
$html = $html.Replace('YOUR-TENANT-ID-HERE', $TenantId)
$html = $html.Replace('const AGENT_URL = "https://YOUR-AGENT-URL-HERE"', 'const AGENT_URL = ""')
Set-Content $webappFile -Value $html -Encoding UTF8

# Rebuild and deploy with the patched webapp
az acr build --registry $ACRName --image "${AppName}:v1" `
    --file "AIAgent/Dockerfile" "." --no-logs
az containerapp update --name $AppName --resource-group $RG `
    --image "${ACRName}.azurecr.io/${AppName}:v1" -o none
```

---

## Post-Deployment Manual Steps

These steps cannot be automated and require manual action in the Azure Portal or Entra admin center:

### 1. Entra ID Directory Roles (Requires Global Admin)

Go to **entra.microsoft.com** → Enterprise applications → `ESIQNew-identity` → Assign roles:
- `Directory Reader` — Needed for Entra collectors to read tenant data
- `Global Reader` — Needed for comprehensive posture assessment

### 2. Admin Consent for Graph Permissions

Go to **entra.microsoft.com** → App registrations → `ESIQNew-Dashboard`:
1. API Permissions → Add delegated permissions
2. Grant admin consent for the tenant

### 3. Teams App Setup (If Using Teams)

See [Teams Integration Guide](07-teams-integration.md) for complete instructions.

Summary:
1. Update `teams/appPackage/manifest.json` with your app registration client ID
2. Build the Teams app package (ZIP)
3. Upload to Teams Admin Center → Manage apps → Upload custom app
4. Publish to your organisation's app store

### 4. DNS / Custom Domain (Optional)

If you want a custom domain instead of `*.azurecontainerapps.io`:
1. Container Apps Environment → Custom domains → Add
2. Create a CNAME record pointing to the FQDN
3. Upload or generate a TLS certificate

---

## Verification Checklist

After deployment, verify each component:

```powershell
# 1. Resource group exists
az group show --name $RG -o table

# 2. AI Services is running
az cognitiveservices account show --name $AIName --resource-group $RG `
    --query "{name:name, state:properties.provisioningState}" -o table

# 3. Models are deployed
az cognitiveservices account deployment list --name $AIName --resource-group $RG -o table

# 4. Container app is running
az containerapp show --name $AppName --resource-group $RG `
    --query "{name:name, fqdn:properties.configuration.ingress.fqdn, status:properties.runningStatus}" -o table

# 5. Health check
$FQDN = az containerapp show --name $AppName --resource-group $RG `
    --query "properties.configuration.ingress.fqdn" -o tsv
Invoke-RestMethod "https://$FQDN/health"

# 6. Storage container exists
az storage container show --name "reports" --account-name $StorageName --auth-mode login -o table

# 7. RBAC roles assigned
az role assignment list --assignee $PrincipalId --all -o table
```

---

## Quick Redeployment (Code Changes Only)

When you only need to update the application code (not infrastructure):

```powershell
$Tag = "v" + (Get-Date -Format "yyyyMMddHHmm")

# 1. Build new image
az acr build --registry $ACRName --image "${AppName}:$Tag" `
    --file "AIAgent/Dockerfile" "." `
    --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss') --no-logs

# 2. Update container
az containerapp update --name $AppName --resource-group $RG `
    --image "${ACRName}.azurecr.io/${AppName}:$Tag" -o table

# 3. Restart active revision
$rev = az containerapp revision list --name $AppName --resource-group $RG `
    --query "[?properties.active].name" -o tsv
az containerapp revision restart --name $AppName --resource-group $RG --revision $rev
```

---

**Next:** [Authentication Flow →](05-authentication-flow.md)
