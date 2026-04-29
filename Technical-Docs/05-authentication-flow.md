# Authentication Flow

> How users and services authenticate — MSAL, Teams SSO, and managed identity.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · **Authentication** · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## Three Authentication Modes

PostureIQ supports three authentication modes depending on where the user accesses the application:

| Mode | Where | Technology | Token Type |
|------|-------|-----------|------------|
| **Web SPA** | Browser (standalone) | MSAL.js v5.6.3 | User-delegated (MSAL popup/redirect) |
| **Teams Tab** | Microsoft Teams | TeamsJS SDK v2.31.1 + MSAL NAA | User-delegated (Teams SSO) |
| **Foundry Agent** | ai.azure.com | Managed Identity | Service principal (DefaultAzureCredential) |

---

## Mode 1: Web SPA Authentication

When a user opens PostureIQ in a browser directly:

```
User opens https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io
    │
    ├── 1. Page loads, MSAL.js initializes
    │      PublicClientApplication({
    │        auth: {
    │          clientId: "ffb6f10d-6991-430e-b3d6-23a0101a92b1",
    │          authority: "https://login.microsoftonline.com/{tenantId}",
    │          redirectUri: window.location.origin
    │        }
    │      })
    │
    ├── 2. Check for cached session
    │      └── ssoSilent() attempt
    │          ├── Success? → Use cached tokens
    │          └── Fail? → Show login button
    │
    ├── 3. User clicks login
    │      └── loginPopup() or loginRedirect()
    │          └── Azure AD login page
    │              └── User enters credentials + MFA
    │                  └── Returns to app with auth code
    │
    ├── 4. Acquire tokens silently for each API
    │      ├── Graph token:
    │      │   acquireTokenSilent({
    │      │     scopes: ["https://graph.microsoft.com/.default"]
    │      │   })
    │      │
    │      └── ARM token:
    │          acquireTokenSilent({
    │            scopes: ["https://management.azure.com/.default"]
    │          })
    │
    └── 5. Send tokens with every API request
           POST /chat
           {
             "message": "Run PostureIQ for FedRAMP",
             "graph_token": "eyJ0eXAiOiJKV...",
             "arm_token": "eyJ0eXAiOiJKV...",
             "page": "SecurityComplianceAssessment"
           }
```

### Token Scopes

| Token | Scope | What It Accesses |
|-------|-------|-----------------|
| Graph | `https://graph.microsoft.com/.default` | Entra ID, users, policies, roles, audit logs |
| ARM | `https://management.azure.com/.default` | Azure subscriptions, resources, Defender, Security Center |

### Why Two Tokens?

Azure Resource Manager and Microsoft Graph are separate APIs with separate audiences. A single token cannot access both. PostureIQ needs:
- **Graph token** → to read Entra ID data (users, policies, roles)
- **ARM token** → to read Azure resources (VMs, storage, networking)

---

## Mode 2: Teams Tab Authentication (NAA)

When a user opens PostureIQ as a Teams tab:

```
User opens PostureIQ tab in Microsoft Teams
    │
    ├── 1. Detect Teams context
    │      microsoftTeams.app.initialize()
    │      └── Gets context.user.tenant.id
    │
    ├── 2. Create Nested App Auth (NAA) MSAL instance
    │      createNestablePublicClientApplication({
    │        auth: {
    │          clientId: "ffb6f10d-...",
    │          supportsNestedAppAuth: true
    │        }
    │      })
    │
    ├── 3. Silent SSO via Teams (no popup needed)
    │      └── ssoSilent({
    │            loginHint: context.user.loginHint,
    │            scopes: ["User.Read"]
    │          })
    │          └── Teams provides token without user interaction
    │
    ├── 4. Acquire Graph + ARM tokens
    │      ├── acquireTokenSilent({ scopes: ["https://graph.microsoft.com/.default"] })
    │      └── acquireTokenSilent({ scopes: ["https://management.azure.com/.default"] })
    │
    └── 5. Same API calls as Web SPA
           POST /chat { message, graph_token, arm_token, page }
```

### What Is NAA (Nested App Authentication)?

NAA is Microsoft's recommended approach for Teams tabs (replacing the older `getAuthToken()` approach). It allows MSAL.js to run inside a Teams iframe and leverage the user's existing Teams session for SSO.

Key benefits:
- **No popup required** — the user is already logged into Teams
- **Same code path** — after initial auth, the code is identical to the SPA flow
- **Falls back to popup** — if silent SSO fails (rare), MSAL opens a popup

### Detection Logic

```javascript
// Simplified from webapp JS
async function initAuth() {
  try {
    // Try Teams first
    await microsoftTeams.app.initialize();
    const context = await microsoftTeams.app.getContext();
    // We're in Teams — use NAA
    msalInstance = await createNestablePublicClientApplication(msalConfig);
    await msalInstance.ssoSilent({ loginHint: context.user.loginHint });
  } catch {
    // Not in Teams — use standard SPA
    msalInstance = new PublicClientApplication(msalConfig);
    await msalInstance.ssoSilent();
  }
}
```

---

## Mode 3: Foundry Agent Authentication

When running as a Foundry Agent (via ai.azure.com), the application authenticates using the managed identity instead of user tokens:

```
User interacts via Foundry Agent UI (ai.azure.com)
    │
    ├── 1. Foundry invokes the agent's API endpoint
    │      (Managed by Azure Foundry runtime)
    │
    ├── 2. Agent code uses DefaultAzureCredential
    │      └── ManagedIdentityCredential(client_id=AZURE_CLIENT_ID)
    │
    ├── 3. Token acquisition is automatic
    │      ├── ARM token: credential.get_token("https://management.azure.com/.default")
    │      └── Graph token: credential.get_token("https://graph.microsoft.com/.default")
    │
    └── 4. No user login needed
           The managed identity has its own RBAC permissions
```

### Limitation

In Foundry Agent mode, the data collected reflects the **managed identity's permissions**, not the user's. The managed identity has `Reader`, `Security Reader`, and Graph API application permissions — this is usually broader than an individual user's access.

---

## Token Flow Through the API

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  Browser  │  POST /chat        │  API     │                    │  Azure   │
│          │  {                  │  Server  │                    │  APIs    │
│          │    graph_token,     │          │                    │          │
│          │    arm_token,       │          │                    │          │
│          │    message          │          │                    │          │
│          │  }                  │          │                    │          │
│          │────────────────────►│          │                    │          │
│          │                    │          │                    │          │
│          │                    │  1. Decode ARM JWT             │          │
│          │                    │     Extract tenant_id          │          │
│          │                    │                                │          │
│          │                    │  2. Create UserTokenCredential │          │
│          │                    │     (wraps user's tokens)      │          │
│          │                    │                                │          │
│          │                    │  3. Call collector              │          │
│          │                    │     collector.collect(          │          │
│          │                    │       arm_cred, graph_cred     │          │
│          │                    │     )                          │          │
│          │                    │────────────────────────────────►│          │
│          │                    │                                │          │
│          │                    │  4. Azure returns data         │          │
│          │                    │◄────────────────────────────────│          │
│          │                    │                                │          │
│          │  SSE: results      │                                │          │
│          │◄────────────────────│                                │          │
└──────────┘                    └──────────┘                    └──────────┘
```

### Security Properties

| Property | Detail |
|----------|--------|
| Token storage | In-memory only (not persisted to disk or database) |
| Token lifetime | Managed by Azure AD (~60-90 minutes, auto-refreshed by MSAL) |
| Token validation | JWT signature verified, `aud` and `iss` claims checked |
| Token forwarding | User tokens forwarded to Azure APIs (delegated access) |
| No shared keys | `allowSharedKeyAccess: false` on storage account |
| HTTPS only | All token transmission over TLS |

---

## Entra App Registration Details

| Property | Value |
|----------|-------|
| Display Name | `EnterpriseSecurityIQ-SPA` |
| Application (client) ID | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` |
| Sign-in audience | `AzureADMyOrg` (single tenant) |
| Platform | Single Page Application (SPA) |
| Redirect URIs | `http://localhost:8080`, `https://esiqnew-agent.....azurecontainerapps.io` |
| ID tokens | Enabled |
| Access tokens | Enabled |

### Delegated Permissions (User Consent)

| API | Permission | Type |
|-----|-----------|------|
| Microsoft Graph | `User.Read` | Delegated |
| Microsoft Graph | `Directory.Read.All` | Delegated (admin consent) |
| Microsoft Graph | `Policy.Read.All` | Delegated (admin consent) |
| Azure Service Management | `user_impersonation` | Delegated |

---

## Common Authentication Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `AADSTS65001` | Admin consent not granted | Portal → App registrations → Grant admin consent |
| `AADSTS700054` | Invalid redirect URI | Ensure FQDN matches registered redirect URI |
| `interaction_required` | Silent token fails | User needs to re-authenticate (session expired) |
| `401 Unauthorized` on `/chat` | Missing or expired tokens | Re-acquire tokens via MSAL |
| `403 AuthorizationFailed` on blob | RBAC not assigned | Assign `Storage Blob Data Contributor` to identity |

See [Troubleshooting](08-troubleshooting.md) for more details.

---

**Next:** [API Reference →](06-api-reference.md)
