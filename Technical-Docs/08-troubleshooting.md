# Troubleshooting

> Common issues, their causes, and how to fix them.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · **Troubleshooting**

---

## Authentication Issues

### "Login failed" or AADSTS errors

| Error Code | Meaning | Fix |
|-----------|---------|-----|
| `AADSTS65001` | Admin consent not granted for permissions | Go to Entra ID → App registrations → `ESIQNew-Dashboard` → API Permissions → Grant admin consent |
| `AADSTS700054` | Redirect URI mismatch | Check that the Container App FQDN exactly matches the registered redirect URI in the app registration |
| `AADSTS50011` | Reply URL does not match | Same as above — ensure `https://your-fqdn` is registered as a SPA redirect URI |
| `AADSTS90002` | Tenant not found | Verify `AZURE_TENANT_ID` environment variable on the container |
| `AADSTS7000218` | Missing `client_assertion` or `client_secret` | The app registration must be configured as SPA (not web/confidential). Check platform configuration |

### "interaction_required" in Teams

**Cause:** Teams SSO (NAA) failed silently and needs user interaction.

**Fix:**
1. Clear Teams cache: Settings → About → Clear Cache
2. Sign out and back into Teams
3. If persists, check that the Entra app has `User.Read` delegated permission with admin consent

### 401 Unauthorized on /chat

**Cause:** The `graph_token` or `arm_token` in the request is missing, expired, or malformed.

**Fix:**
1. Open browser DevTools → Network → find the `/chat` request
2. Check the request body has both `graph_token` and `arm_token`
3. If tokens are present, they may be expired — refresh the page (MSAL will acquire new tokens)
4. Check for JavaScript console errors related to `acquireTokenSilent`

---

## Report and Storage Issues

### Reports Fail to Download (404)

**Symptoms:** Clicking a report link returns "Report not found".

**Causes and fixes:**

| Cause | How to Check | Fix |
|-------|-------------|-----|
| Container restarted (local files lost) | `az containerapp revision list --name esiqnew-agent --resource-group ESIQNew-RG` | Reports should auto-download from blob. If blob upload also failed, re-run the assessment |
| Blob upload failed | Check container logs for `upload_directory` errors | See "Blob Upload Failures" below |
| Path encoding issue | Check if the URL has special characters | URL-encode the path |

### Blob Upload Failures (AuthorizationFailure)

**Symptoms:** Container logs show `AuthorizationFailure` when uploading to blob storage.

**Most common causes:**

1. **publicNetworkAccess disabled on storage account**
   ```powershell
   # Check current setting
   az storage account show --name esiqnewstorage --resource-group ESIQNew-RG `
       --query "properties.publicNetworkAccess" -o tsv

   # Fix: enable public access (required — container has no VNet)
   az storage account update --name esiqnewstorage --resource-group ESIQNew-RG `
       --public-network-access Enabled -o none
   ```

2. **RBAC role not assigned**
   ```powershell
   # Verify the managed identity has Storage Blob Data Contributor
   $PrincipalId = az identity show --name ESIQNew-identity --resource-group ESIQNew-RG `
       --query "principalId" -o tsv
   az role assignment list --assignee $PrincipalId --scope $(
       az storage account show --name esiqnewstorage --resource-group ESIQNew-RG --query "id" -o tsv
   ) -o table

   # If missing, assign it
   az role assignment create --assignee $PrincipalId `
       --role "Storage Blob Data Contributor" `
       --scope $(az storage account show --name esiqnewstorage --resource-group ESIQNew-RG --query "id" -o tsv) -o none
   ```

3. **Managed identity not configured on container**
   ```powershell
   az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG `
       --query "identity.userAssignedIdentities" -o json
   ```
   Should show the `ESIQNew-identity` resource ID.

4. **RBAC propagation delay**
   After assigning a new RBAC role, wait 5–10 minutes for propagation.

---

## Container Issues

### Container Won't Start (CrashLoopBackOff)

**Check logs:**
```powershell
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --follow
```

**Common causes:**

| Error in Logs | Cause | Fix |
|--------------|-------|-----|
| `ModuleNotFoundError` | Missing Python package | Check `requirements.txt` includes all dependencies, rebuild image |
| `Port 8088 already in use` | Port conflict | Should not happen in Container Apps — restart the revision |
| `playwright install chromium` errors | Chromium not installed in image | The Dockerfile should include `RUN playwright install chromium`. Rebuild |
| `AZURE_OPENAI_ENDPOINT not set` | Missing environment variable | Set env var on the container app |
| `uvicorn.error` | App code syntax error | Read the full traceback in logs |

### Container Restarts Frequently

**Check:**
```powershell
az containerapp revision list --name esiqnew-agent --resource-group ESIQNew-RG -o table
```

**Common causes:**
- Memory limit exceeded (2 GiB) — happens during large assessments with many collectors + PDF generation running simultaneously
- Liveness probe failure — the `/health` endpoint must respond within the timeout
- Unhandled exception in a background task

**Fix:** If memory is the issue, increase memory:
```powershell
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG `
    --cpu 1 --memory "4Gi" -o none
```

### How to View Container Logs

```powershell
# Recent logs
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --tail 100

# Follow logs in real-time
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --follow

# Query via Log Analytics (more powerful)
az monitor log-analytics query --workspace ESIQNew-law `
    --analytics-query "ContainerAppConsoleLogs_CL | where ContainerAppName_s == 'esiqnew-agent' | order by TimeGenerated desc | take 50" `
    -o table
```

---

## Assessment Issues

### Assessment Takes Too Long (> 5 Minutes)

**Normal duration:** 2–5 minutes for PostureIQ with 11 frameworks.

**If it takes longer:**
1. Check if the Azure OpenAI models are throttled (429 responses)
2. Check if Graph API calls are being rate-limited
3. Check network latency between Container Apps region and AI Services region

**Monitoring:**
```powershell
# Check Azure OpenAI rate limits
az cognitiveservices account deployment show --name ESIQNew-AI --resource-group ESIQNew-RG `
    --deployment-name gpt-4.1 --query "properties.rateLimits" -o json
```

### Assessment Returns No Findings

**Possible causes:**
1. **Insufficient permissions** — the user's tokens don't have access to read Azure/Entra data
   - The `check_permissions` tool can probe what the user can access
2. **No resources in subscription** — the assessed subscription has no resources
3. **Wrong tenant** — the tokens are for a different tenant than expected

### "Tool execution failed" Error

**Check container logs** for the full stack trace:
```powershell
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --tail 200
```

**Common causes:**
- Azure OpenAI model deployment deleted or renamed
- Graph API permission revoked
- Token expired during a long-running tool (rare — tokens are validated at the start)

---

## Azure OpenAI Issues

### Model Returns Empty Responses

**Cause:** The model deployment may be throttled or the API version may be incorrect.

**Check:**
```powershell
# Test the model endpoint directly
$endpoint = "https://esiqnew-ai.cognitiveservices.azure.com"
$token = az account get-access-token --resource "https://cognitiveservices.azure.com" --query "accessToken" -o tsv

Invoke-RestMethod -Uri "$endpoint/openai/deployments/gpt-5.1/chat/completions?api-version=2025-01-01-preview" `
    -Method POST -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body '{"messages":[{"role":"user","content":"Hello"}]}'
```

### 429 Too Many Requests

**Cause:** Token rate limit exceeded (30K TPM per model).

**Fix options:**
1. Wait for the rate limit window to reset (usually 60 seconds)
2. Increase TPM capacity:
   ```powershell
   az cognitiveservices account deployment create `
       --name ESIQNew-AI --resource-group ESIQNew-RG `
       --deployment-name gpt-5.1 `
       --model-name gpt-5.1 --model-version "2025-11-13" `
       --model-format "OpenAI" --sku-name Standard --sku-capacity 60 -o none
   ```
3. The app has built-in retry logic with `Retry-After` header handling

---

## Deployment Issues

### ACR Build Fails

```powershell
# Check build logs
az acr task logs --registry esiqnewacr
```

**Common causes:**
- Dockerfile syntax error
- Python package installation failure (network issues in ACR build environment)
- File not found (ensure the build context includes all required files)

### Container App Update Fails

```powershell
# Check the container app status
az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG `
    --query "{name:name, provisioningState:properties.provisioningState, runningStatus:properties.runningStatus}" -o json
```

### Image Pull Failure

**Symptoms:** Container shows `ImagePullBackOff`.

**Fix:**
1. Verify the managed identity has `AcrPull` role:
   ```powershell
   $PrincipalId = az identity show --name ESIQNew-identity --resource-group ESIQNew-RG --query "principalId" -o tsv
   az role assignment list --assignee $PrincipalId --scope $(az acr show --name esiqnewacr --resource-group ESIQNew-RG --query "id" -o tsv) -o table
   ```
2. Verify the image exists in the registry:
   ```powershell
   az acr repository show-tags --name esiqnewacr --repository esiqnew-agent -o table
   ```

---

## Teams-Specific Issues

### PostureIQ Tab Shows Blank Page

1. **Check `validDomains`** in `manifest.json` — must include the container app FQDN
2. **Check CSP headers** — the container must send `frame-ancestors` allowing Teams domains
3. **Check browser console** — look for `Refused to display ... in a frame` errors

### Teams SSO Fails

1. Verify `webApplicationInfo.id` in manifest matches the Entra app registration
2. Verify `webApplicationInfo.resource` matches `api://{clientId}`
3. Ensure the Entra app has `User.Read` delegated permission with admin consent
4. Try clearing Teams cache: Settings → About → Clear Cache

### Reports Don't Open from Teams

In Teams, report links should open in a new browser tab (`target="_blank"`). If they open inside the iframe:
1. Check that the HTML page uses `target="_blank"` on all report links
2. Check that `download` attribute is set

---

## Diagnostic Commands Quick Reference

```powershell
# ── Container ──
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --tail 50
az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG -o json
az containerapp revision list --name esiqnew-agent --resource-group ESIQNew-RG -o table

# ── Storage ──
az storage blob list --container-name reports --account-name esiqnewstorage --auth-mode login -o table
az storage account show --name esiqnewstorage --resource-group ESIQNew-RG --query "properties.publicNetworkAccess"

# ── AI Services ──
az cognitiveservices account show --name ESIQNew-AI --resource-group ESIQNew-RG -o json
az cognitiveservices account deployment list --name ESIQNew-AI --resource-group ESIQNew-RG -o table

# ── RBAC ──
$pid = az identity show --name ESIQNew-identity --resource-group ESIQNew-RG --query "principalId" -o tsv
az role assignment list --assignee $pid --all -o table

# ── Health ──
$fqdn = az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG --query "properties.configuration.ingress.fqdn" -o tsv
Invoke-RestMethod "https://$fqdn/health"
```

---

**Back to:** [Index →](index-of-tech-docs.md)
