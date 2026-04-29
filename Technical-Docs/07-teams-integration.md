# Teams Integration

> How PostureIQ runs as a Microsoft Teams tab — manifest, NAA, and iframe behaviour.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · [Reports](03-report-lifecycle.md) · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · **Teams Integration** · [Troubleshooting](08-troubleshooting.md)

---

## Overview

PostureIQ can run inside Microsoft Teams as a personal tab. The Teams version is a separate HTML page (`Teams-SecurityComplianceAssessment.html`) that uses the same backend API but includes Teams-specific JavaScript for SSO and iframe handling.

---

## Teams App Package

The Teams app package is located at `teams/appPackage/build/PostureIQ.zip`.

### Manifest Structure

```
PostureIQ.zip
  ├── manifest.json      ← App definition (v1.22)
  ├── color.png          ← 192×192 full-color icon
  └── outline.png        ← 32×32 outline icon
```

### Manifest Key Fields

```json
{
  "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.22/MicrosoftTeams.schema.json",
  "manifestVersion": "1.22",
  "version": "1.0.6",
  "id": "{app-registration-id}",
  "name": {
    "short": "PostureIQ",
    "full": "PostureIQ — Security Posture Assessment"
  },
  "staticTabs": [
    {
      "entityId": "posture",
      "name": "PostureIQ",
      "contentUrl": "https://esiqnew-agent.....azurecontainerapps.io/Teams-SecurityComplianceAssessment.html",
      "websiteUrl": "https://esiqnew-agent.....azurecontainerapps.io/SecurityComplianceAssessment.html",
      "scopes": ["personal"]
    }
  ],
  "permissions": ["identity", "messageTeamMembers"],
  "validDomains": [
    "esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io"
  ],
  "webApplicationInfo": {
    "id": "{app-registration-client-id}",
    "resource": "api://{app-registration-client-id}"
  },
  "authorization": {
    "permissions": {
      "resourceSpecific": [
        {
          "name": "TeamsActivity.Send.User",
          "type": "Application"
        }
      ]
    }
  }
}
```

### Key Points

| Field | Purpose |
|-------|---------|
| `staticTabs[].contentUrl` | The Teams-specific HTML page loaded in the iframe |
| `staticTabs[].websiteUrl` | Fallback URL when opening outside Teams |
| `validDomains` | Container App FQDN — Teams only allows content from listed domains |
| `webApplicationInfo.id` | Same Entra App Registration client ID used by MSAL |
| `authorization` | Resource-specific consent for Teams features |

---

## Teams-Specific HTML Page

`Teams-SecurityComplianceAssessment.html` is a modified version of the standalone page with these differences:

| Feature | Standalone | Teams |
|---------|-----------|-------|
| Authentication | MSAL popup/redirect | Teams SSO (NAA) |
| Login button | Shown | Hidden (auto-SSO) |
| Page chrome | Full navigation | Minimal (no sidebar, no theme toggle) |
| Theme | User-selected (light/dark) | Matches Teams theme (auto-detected) |
| Links | Open in same window | Open in browser (`target="_blank"`) |
| Report downloads | Direct download | Open in new browser tab |
| iframe embedding | Not embedded | Runs inside Teams iframe |

---

## Nested App Authentication (NAA) Flow

NAA is the authentication mechanism for Teams tabs. It allows MSAL.js to leverage the user's existing Teams session:

```
Teams loads PostureIQ tab (iframe)
    │
    ├── 1. teams-init.js runs
    │      await microsoftTeams.app.initialize()
    │      context = await microsoftTeams.app.getContext()
    │
    ├── 2. Detect Teams theme
    │      microsoftTeams.app.registerOnThemeChangeHandler(handler)
    │      └── Apply 'dark' or 'default' theme to document
    │
    ├── 3. Create NAA MSAL instance
    │      createNestablePublicClientApplication({
    │        auth: {
    │          clientId: "ffb6f10d-...",
    │          authority: "https://login.microsoftonline.com/{tenantId}",
    │          supportsNestedAppAuth: true
    │        }
    │      })
    │
    ├── 4. Silent SSO
    │      ssoSilent({
    │        loginHint: context.user.loginHint,
    │        scopes: ["User.Read"]
    │      })
    │      └── Returns: MSAL account (no user interaction)
    │
    ├── 5. Acquire API tokens
    │      acquireTokenSilent({ scopes: ["https://graph.microsoft.com/.default"] })
    │      acquireTokenSilent({ scopes: ["https://management.azure.com/.default"] })
    │
    └── 6. Ready — user can run assessments
```

### Fallback to Popup

If silent SSO fails (unlikely in Teams, but possible with consent issues):

```
ssoSilent() fails with interaction_required
    │
    └── loginPopup({
          scopes: ["User.Read"],
          loginHint: context.user.loginHint
        })
        └── Teams opens auth popup
            └── User consents → returns account
```

---

## Theme Synchronisation

Teams provides its current theme to embedded tabs. PostureIQ synchronises:

```javascript
// teams-init.js
microsoftTeams.app.registerOnThemeChangeHandler((theme) => {
  if (theme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
  }
});
```

The Fluent 2 CSS theme system (`theme.css`) uses CSS custom properties that respond to `data-theme`:
- `data-theme="light"` → Light mode colours
- `data-theme="dark"` → Dark mode colours

---

## iframe Security

### Content Security Policy

The Container App sends CSP headers allowing Teams to embed the page:

```
Content-Security-Policy:
  frame-ancestors https://teams.microsoft.com
                  https://*.office.com
                  https://*.cloud.microsoft
                  https://*.microsoft365.com
```

### CORS Headers

The API allows cross-origin requests from Teams domains:

```
Access-Control-Allow-Origin: https://teams.microsoft.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: *
```

---

## Installing the Teams App

### Method 1: Teams Admin Center (Organisation-Wide)

1. Go to **Teams Admin Center** → Manage apps → Upload new app
2. Upload `PostureIQ.zip` from `teams/appPackage/build/`
3. Review app settings and approve
4. Set availability policy (all users, specific groups, etc.)
5. Users will see PostureIQ in their Teams app list

### Method 2: Sideload (Development/Testing)

1. In Teams, go to Apps → Manage your apps → Upload a custom app
2. Select `PostureIQ.zip`
3. Click Add — the tab appears in your personal app list

### Method 3: Teams Toolkit (VS Code)

If you have Teams Toolkit installed in VS Code:
1. Open the `teams/` directory
2. Use Teams Toolkit → Provision → Deploy
3. Preview in Teams

---

## Building the Teams App Package

### Update manifest.json

```powershell
# In teams/appPackage/manifest.json, replace:
# - {app-registration-id} with your Entra app registration ID
# - contentUrl with your container app FQDN
# - validDomains with your container app FQDN
```

### Create the ZIP

```powershell
cd teams/appPackage
Compress-Archive -Path manifest.json, color.png, outline.png -DestinationPath build/PostureIQ.zip -Force
```

### Validate

Use the [Teams App Validation Tool](https://dev.teams.microsoft.com/appvalidation.html) to check the manifest before uploading.

---

## Differences from Standalone

### Report Downloads

In Teams, report links use `target="_blank"` with a `download` attribute to open in the user's default browser instead of navigating within the Teams iframe:

```html
<a href="/reports/20260422/.../report.html"
   target="_blank"
   download="fedramp-compliance-report.html">
  📄 HTML
</a>
```

### Navigation

The Teams version hides the sidebar navigation and assessment-type selector. The user interacts only through the chat interface. The page name is fixed to `SecurityComplianceAssessment` (PostureIQ) in the Teams manifest.

### Session Storage

Both versions use `localStorage` for session persistence. In Teams, `localStorage` is scoped to the iframe origin, so sessions are separate from the standalone version.

---

**Next:** [Troubleshooting →](08-troubleshooting.md)
