# PostureIQ — Teams Integration Implementation Guide

> **Status**: Production — v89 (Teams Desktop) / v1.0.5 manifest (Teams Web)  
> **Last Updated**: April 2026  
> **Manifest Schema**: v1.22 with Nested App Auth (NAA)  
> **Auth**: MSAL.js v5.6.3 with `createNestablePublicClientApplication()`

---

## 1. Overview

PostureIQ is embedded into Microsoft Teams as a **personal Tab app**. The full webapp
runs inside a Teams-hosted `<iframe>`, preserving 100% of existing functionality
including all report generation, downloads, and the AI chat interface.

### Design Principles

| Principle | Detail |
|-----------|--------|
| **Zero feature loss** | Every page and capability works identically inside Teams and in a standalone browser. |
| **Graceful degradation** | The Teams SDK initialization is a no-op when the app runs outside Teams. |
| **Single codebase** | No Teams-specific fork — the same HTML/JS/CSS served in both contexts. |
| **Theme synchronisation** | The app detects the Teams theme (dark / light / high-contrast) and maps it to the existing `data-theme` attribute on `<html>`. |
| **NAA-first auth** | Uses Nested App Auth for cookie-less token acquisition (required for Teams Web). |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   Microsoft Teams (Desktop / Web)             │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Personal Tab (iframe)                                 │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Teams-SecurityComplianceAssessment.html         │  │  │
│  │  │  ┌────────────┐  ┌───────────────────────────┐  │  │  │
│  │  │  │ TeamsJS    │  │ MSAL.js v5.6.3 (NAA)      │  │  │  │
│  │  │  │ v2.31.1    │  │ createNestablePublicClient │  │  │  │
│  │  │  │ + init.js  │  │ → Graph + ARM tokens       │  │  │  │
│  │  │  └────────────┘  └───────────────────────────────┘  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                         │ SSE /chat                           │
│                         ▼                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Azure Container Apps (FastAPI backend)                │  │
│  │  esiqnew-agent.<hash>.northeurope.azurecontainerapps.io│  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Manifest (v1.22)

**Template**: `teams/appPackage/manifest.json`  
**Build output**: `teams/appPackage/build/manifest.json`

| Field | Value |
|-------|-------|
| Schema | `v1.22/MicrosoftTeams.schema.json` |
| Manifest version | `1.22` |
| App version | `1.0.5` |
| App ID | `{{TEAMS_APP_ID}}` (Entra App client ID) |
| Static tabs | 1 — Security Assessment |
| `webApplicationInfo.id` | `{{TEAMS_APP_ID}}` |
| `webApplicationInfo.resource` | `api://{{BACKEND_FQDN}}/{{TEAMS_APP_ID}}` |
| `nestedAppAuthInfo` | `brk-multihub://{{BACKEND_FQDN}}` redirect + CP1 claims |
| `validDomains` | `{{BACKEND_FQDN}}`, `login.microsoftonline.com` |
| `showLoadingIndicator` | `true` |

### Why v1.22 (not v1.17)

Manifest v1.22 introduced the `nestedAppAuthInfo` field inside `webApplicationInfo`.
This field tells Teams that the app uses **Nested App Auth (NAA)** for token acquisition
instead of third-party cookies. Without it, Teams Web shows a warning:
"This app may have issues in the web version of Teams."

### nestedAppAuthInfo block

```json
"nestedAppAuthInfo": [
  {
    "redirectUri": "brk-multihub://{{BACKEND_FQDN}}",
    "scopes": ["openid", "profile", "offline_access"],
    "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}"
  }
]
```

- **`redirectUri`**: The `brk-multihub://` scheme enables the Teams broker to handle auth
- **`scopes`**: Standard OIDC scopes for NAA
- **`claims`**: CP1 = Client capabilities claim for Continuous Access Evaluation (CAE)

---

## 4. Authentication — Nested App Auth (NAA)

### What is NAA?

Nested App Auth allows an app embedded inside Teams to acquire tokens silently through
the Teams host (the "broker") without popups or third-party cookies. This is critical
for **Teams Web** where third-party cookies are blocked by default.

### Auth Flow (Inside Teams)

```
1. teams-init.js detects Teams context → sets window.__esiqInTeams = true
2. MSAL_CONFIG sets supportsNestedAppAuth: true, cacheLocation: "localStorage"
3. initMsal() calls msal.createNestablePublicClientApplication(MSAL_CONFIG)
4. Token requests flow through Teams broker → silent token acquisition
5. Fallback: if NAA fails → msal.createPublicClientApplication() (popup auth)
```

### Auth Flow (Standalone Browser)

```
1. teams-init.js detects NOT in Teams → window.__esiqInTeams = false
2. initMsal() creates standard PublicClientApplication
3. Token requests use popup/redirect against login.microsoftonline.com
```

### MSAL Configuration

```javascript
const MSAL_CONFIG = {
  auth: {
    clientId: "<ENTRA_APP_ID>",
    authority: "https://login.microsoftonline.com/common",
    supportsNestedAppAuth: true,
    redirectUri: window.location.origin
  },
  cache: { cacheLocation: "localStorage" }
};
```

### Critical: localStorage, NOT sessionStorage

MSAL's token cache **MUST** use `localStorage`. Using `sessionStorage` causes 401 errors
in Teams Desktop because Teams opens tabs in separate processes that don't share
sessionStorage. This was a production incident at v88 — see Troubleshooting section below.

---

## 5. Entra App Registration Requirements

### Application ID URI

```
api://<BACKEND_FQDN>/<ENTRA_APP_ID>
```

### Exposed API Scope

| Scope | Type | Description |
|-------|------|-------------|
| `access_as_user` | User (delegated) | Access PostureIQ as signed-in user |

### SPA Redirect URIs (6 required)

| URI | Purpose |
|-----|---------|
| `https://<FQDN>/Teams-SecurityComplianceAssessment.html` | Teams tab content URL |
| `https://<FQDN>/SecurityComplianceAssessment.html` | Standalone webapp |
| `https://<FQDN>/auth-end.html` | Auth callback |
| `brk-multihub://<FQDN>` | NAA broker redirect (Teams) |
| `http://localhost:8088` | Local dev |
| `http://localhost:8090` | Local dev |

### Web Redirect URIs

| URI | Purpose |
|-----|---------|
| `https://<FQDN>/auth-end.html` | Auth callback (web platform) |

### Pre-Authorized Client Applications (7 required)

All must be authorized for the `access_as_user` scope:

| Client | Application ID | Purpose |
|--------|---------------|---------|
| Teams desktop/mobile | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Teams native apps |
| Teams web | `5e3ce6c0-2b1f-4285-8d4b-75ee78787346` | teams.microsoft.com / teams.cloud.microsoft |
| Microsoft 365 web | `4765445b-32c6-49b0-83e6-1d93765276ca` | office.com (new Teams) |
| Microsoft 365 desktop | `0ec893e0-5785-4de6-99da-4ed124e5296c` | M365 desktop app |
| M365 mobile / Outlook desktop | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Mobile + Outlook |
| Outlook web | `bc59ab01-8403-45c6-8796-ac3ef710b3e3` | outlook.office.com |
| Outlook mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` | Outlook mobile app |

> **Important**: Without all 7 pre-authorized clients, NAA will fail silently on certain
> platforms. The Teams Desktop/Web IDs alone are not sufficient for full M365 coverage.

---

## 6. Backend Configuration (FastAPI)

### CORS Origins

```python
_DEFAULT_ORIGINS = [
    "http://localhost:8088",
    "http://localhost:8090",
    "https://teams.microsoft.com",
    "https://*.teams.microsoft.com",
    "https://teams.cloud.microsoft",
    "https://*.office.com",
    "https://*.microsoft365.com",
]
```

### CSP frame-ancestors

```python
_FRAME_ANCESTORS = (
    "frame-ancestors 'self' "
    "https://teams.microsoft.com https://*.teams.microsoft.com "
    "https://teams.cloud.microsoft https://*.cloud.microsoft "
    "https://*.office.com https://*.microsoft365.com https://*.microsoft.com"
)
```

Both CORS and CSP must include `teams.cloud.microsoft` — this is the new Teams Web domain
that coexists with `teams.microsoft.com`.

---

## 7. Teams SDK Integration

### Script Loading Order (every HTML page)

```html
<script src="https://res.cdn.office.net/teams-js/2.31.1/js/MicrosoftTeams.min.js"></script>
<script src="/teams-init.js"></script>
<script src="/msal-browser.min.js"></script>
```

### teams-init.js Behaviour

1. **Detection** — checks four signals to determine if running inside Teams:
   - `window.parent !== window` (iframe)
   - `window.name === "embedded-page-container"` (Teams iframe name)
   - User-Agent contains `Teams`
   - URL query parameter `?inTeams=true`
2. **Sets flag** — `window.__esiqInTeams = true` (used by MSAL init logic)
3. **Initialization** — `microsoftTeams.app.initialize(["https://teams.cloud.microsoft"])`
4. **Signals** — `notifyAppLoaded()` + `notifySuccess()` (hides Teams loading spinner)
5. **Theme sync** — reads Teams theme → maps to `data-theme` attribute
6. **Live theme handler** — `registerOnThemeChangeHandler()` for runtime changes
7. **No-op fallback** — when not in Teams, the script does nothing

### validMessageOrigins

The `initialize()` call includes `https://teams.cloud.microsoft` as a valid message origin.
This is required for the new Teams Web client.

---

## 8. Deployment Script — Deploy-TeamsApp.ps1

### Location

`teams/appPackage/Deploy-TeamsApp.ps1`

### Modes

| Mode | Description |
|------|-------------|
| `Validate` | Check manifest validity, icons, backend health |
| `Build` | Resolve template → validate → create PostureIQ.zip |
| `Sideload` | Build + upload as custom app (personal/testing) |
| `OrgPublish` | Build + submit to org catalog (all users) |
| `EntraConfig` | Configure Entra app registration (scope, redirects, pre-authorized clients) |
| `Full` | EntraConfig → Build → Sideload in one command |

### Usage

```powershell
# New tenant — complete setup
.\Deploy-TeamsApp.ps1 `
    -EntraAppId "<ENTRA_APP_CLIENT_ID>" `
    -BackendFqdn "<CONTAINER_APP_FQDN>" `
    -Mode Full

# Just configure Entra (if manifest already deployed)
.\Deploy-TeamsApp.ps1 `
    -EntraAppId "<ENTRA_APP_CLIENT_ID>" `
    -BackendFqdn "<CONTAINER_APP_FQDN>" `
    -Mode EntraConfig

# Build package only
.\Deploy-TeamsApp.ps1 `
    -EntraAppId "<ENTRA_APP_CLIENT_ID>" `
    -BackendFqdn "<CONTAINER_APP_FQDN>" `
    -Mode Build
```

### What EntraConfig Does (4 idempotent steps)

1. **Application ID URI** — Sets `api://<FQDN>/<AppId>` if not already set
2. **API scope** — Creates `access_as_user` delegated permission scope
3. **SPA redirect URIs** — Ensures `brk-multihub://`, Teams HTML, and auth-end redirects exist
4. **Pre-authorized clients** — Adds all 7 Microsoft 365 client IDs with `access_as_user` scope

All steps are idempotent — safe to re-run. Requires Azure CLI signed in with sufficient
Entra permissions (Application.ReadWrite.All or owner of the app registration).

---

## 9. Multi-Tenant Deployment Checklist

For deploying PostureIQ to a **new tenant**:

### Prerequisites

- [ ] Azure subscription with Container Apps, ACR, and Azure OpenAI
- [ ] Entra ID app registration created (get the client ID)
- [ ] Azure CLI signed in to the target tenant
- [ ] PowerShell 7+ with `az` CLI

### Steps

1. **Deploy the backend** (Container App + ACR image)
   ```powershell
   # Build and push image
   az acr build --registry <ACR_NAME> --image esiqnew-agent:v89 --file AIAgent/Dockerfile <CONTEXT_DIR>
   # Update container app
   az containerapp update --name <APP_NAME> --resource-group <RG> --image <ACR>.azurecr.io/esiqnew-agent:v89
   ```

2. **Run Full deployment** (Entra + manifest + sideload)
   ```powershell
   .\teams\appPackage\Deploy-TeamsApp.ps1 `
       -EntraAppId "<NEW_TENANT_APP_ID>" `
       -BackendFqdn "<NEW_BACKEND_FQDN>" `
       -Mode Full
   ```

3. **Verify** in Teams Desktop and Teams Web

---

## 10. File Reference

| File | Purpose | Modify? |
|------|---------|---------|
| `teams/appPackage/manifest.json` | Template manifest with `{{placeholders}}` | Edit for schema changes |
| `teams/appPackage/Deploy-TeamsApp.ps1` | Deployment automation script | Edit for new modes |
| `teams/appPackage/build/manifest.json` | Resolved manifest (auto-generated) | Never — auto-generated |
| `teams/appPackage/build/PostureIQ_v1.0.5.zip` | Teams app package (auto-generated) | Never — auto-generated |
| `teams/appPackage/color.png` | 192×192 app icon | Replace with custom branding |
| `teams/appPackage/outline.png` | 32×32 outline icon | Replace with custom branding |
| `webapp/Teams-SecurityComplianceAssessment.html` | Teams-specific SPA (inside tab) | Edit for UI changes |
| `webapp/SecurityComplianceAssessment.html` | Standalone SPA (NOT for Teams) | **NEVER modify** |
| `webapp/teams-init.js` | Teams SDK detection + initialization | Edit for SDK changes |
| `webapp/msal-browser.min.js` | MSAL.js v5.6.3 (self-hosted) | Replace for version upgrades |
| `AIAgent/app/api.py` | FastAPI backend (CORS, CSP, routes) | Edit for backend changes |

> **WARNING**: `SecurityComplianceAssessment.html` (standalone) must NEVER be modified.
> Teams-specific changes go ONLY in `Teams-SecurityComplianceAssessment.html`.

---

## 11. Troubleshooting Guide

### Issue 1: "This app may have issues in the web version of Teams"

**Symptom**: Warning banner appears when opening PostureIQ in Teams Web (`teams.cloud.microsoft`).
Teams Desktop works fine.

**Root Cause**: Manifest missing `nestedAppAuthInfo` field. Teams Web performs a pre-flight
check to determine if the app handles third-party cookie restrictions. Without the
`nestedAppAuthInfo` declaration, Teams assumes the app will break.

**Fix**:
1. Upgrade manifest schema to v1.22 or later
2. Add `nestedAppAuthInfo` block inside `webApplicationInfo`:
   ```json
   "nestedAppAuthInfo": [
     {
       "redirectUri": "brk-multihub://<FQDN>",
       "scopes": ["openid", "profile", "offline_access"],
       "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}"
     }
   ]
   ```
3. Add `brk-multihub://<FQDN>` as a SPA redirect URI in Entra
4. Pre-authorize all 7 Microsoft 365 client IDs (not just Teams 2)
5. Rebuild and re-upload the Teams app package

**Automated Fix**: `.\Deploy-TeamsApp.ps1 -Mode Full`

---

### Issue 2: 401 Unauthorized on API calls (Teams Desktop)

**Symptom**: PostureIQ loads in Teams Desktop but all API calls fail with 401.
Token acquisition appears to succeed but tokens are not found on subsequent requests.

**Root Cause**: MSAL cache using `sessionStorage`. Teams Desktop opens each tab in a
separate process/webview, and `sessionStorage` is NOT shared across processes. Tokens
cached in one process are invisible to the process making API calls.

**Fix**: Set MSAL cache to `localStorage`:
```javascript
cache: { cacheLocation: "localStorage" }
```

**Verification**: Check browser DevTools → Application → Local Storage for
`msal.*` keys containing cached tokens.

> **History**: This was a production regression at v88. Fixed in v89.

---

### Issue 3: MSAL interaction_in_progress error

**Symptom**: Auth flow hangs with "interaction_in_progress" error in console. Subsequent
token requests fail.

**Root Cause**: A previous MSAL popup/redirect was interrupted (user closed popup, network
error, etc.), leaving a stale interaction lock in localStorage.

**Fix**: The app clears stale locks on initialization:
```javascript
Object.keys(localStorage)
  .filter(k => k.includes("interaction.status"))
  .forEach(k => localStorage.removeItem(k));
```

This runs before `createNestablePublicClientApplication()` in `initMsal()`.

---

### Issue 4: App works in Desktop but blank/error in Teams Web

**Symptom**: White screen or JavaScript errors only in Teams Web.

**Possible Causes & Fixes**:

| Cause | Check | Fix |
|-------|-------|-----|
| CSP blocks iframe | Browser DevTools → Console for `frame-ancestors` errors | Add `teams.cloud.microsoft` to `_FRAME_ANCESTORS` in api.py |
| CORS blocks requests | Console for `Access-Control-Allow-Origin` errors | Add `teams.cloud.microsoft` to `_DEFAULT_ORIGINS` in api.py |
| Third-party cookies blocked | Console for storage/cookie errors | Ensure NAA is active (`createNestablePublicClientApplication`) |
| Missing validMessageOrigins | Console for Teams SDK postMessage errors | Add `https://teams.cloud.microsoft` to `initialize()` call |

---

### Issue 5: NAA falls back to popup auth in Teams

**Symptom**: `[NAA] createNestablePublicClientApplication failed` in console, then popup
appears for auth.

**Possible Causes**:

| Cause | Fix |
|-------|-----|
| MSAL.js too old | Use v5.6.3+ which supports `createNestablePublicClientApplication` |
| `supportsNestedAppAuth: true` missing from MSAL config | Add to `auth` section of MSAL_CONFIG |
| `brk-multihub://` SPA redirect not registered in Entra | Add via Portal or `EntraConfig` mode |
| Missing pre-authorized client for the platform | Run `Deploy-TeamsApp.ps1 -Mode EntraConfig` |

---

### Issue 6: Theme mismatch between Teams and PostureIQ

**Symptom**: Teams is in dark mode but PostureIQ shows light mode (or vice versa).

**Root Cause**: `teams-init.js` runs before the page's theme initialization, or the
theme change handler wasn't registered.

**Fix**: Ensure `teams-init.js` is loaded BEFORE any page-specific scripts. The script
handles both initial theme detection and live theme changes via
`registerOnThemeChangeHandler()`.

---

### Issue 7: Deploy-TeamsApp.ps1 EntraConfig fails with "Bad Request"

**Symptom**: `az rest` returns `"Unable to read JSON request payload"`.

**Root Cause**: PowerShell mangles JSON when passed inline to `az rest --body`.
Special characters and quotes get escaped incorrectly.

**Fix**: The script writes JSON to a temp file and uses `--body @<tempfile>` syntax.
This is already implemented in the current version.

---

### Issue 8: Pre-authorized clients not taking effect

**Symptom**: After adding pre-authorized clients, NAA still fails.

**Diagnostic Steps**:
1. Verify in Azure Portal → App registrations → Expose an API → Authorized client applications
2. Ensure each client has the `access_as_user` scope checked
3. Wait 5-10 minutes for Azure AD propagation
4. Clear browser cache and Teams cache
5. Re-run: `.\Deploy-TeamsApp.ps1 -Mode EntraConfig` (idempotent — verifies state)

---

## 12. Version History

| Version | Manifest | Changes |
|---------|----------|---------|
| v73 | 1.17 | Initial Teams tab integration |
| v84-v87 | 1.17 | UI improvements, backend updates |
| v88 | 1.17 | Switched to sessionStorage (**BROKE Teams Desktop**) |
| v89 | 1.17 | Reverted to localStorage (fixed Desktop), confirmed working |
| v89 + v1.0.5 | **1.22** | Added `nestedAppAuthInfo`, pre-authorized all 7 M365 clients, `Deploy-TeamsApp.ps1` EntraConfig/Full modes |

---

## 13. Key Domains Reference

| Domain | Used By |
|--------|---------|
| `teams.microsoft.com` | Teams classic web |
| `teams.cloud.microsoft` | Teams new web client |
| `*.office.com` | M365 / Outlook web |
| `*.microsoft365.com` | M365 portal |
| `login.microsoftonline.com` | Azure AD / Entra login |
| `res.cdn.office.net` | TeamsJS SDK CDN |
