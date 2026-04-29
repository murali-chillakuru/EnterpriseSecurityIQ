"""
Attack Path Detection — Consent / OAuth Abuse evaluator.

Phase 2 Identity: Over-consented OAuth applications that can access
resources beyond their intended scope.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

# Delegated permissions that represent broad data access
_DANGEROUS_SCOPES = {
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Group.ReadWrite.All",
}


def analyze_consent_abuse(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect over-consented OAuth apps that create permission abuse paths."""
    paths: list[dict] = []

    grants = evidence_index.get("entra-oauth2-grant", [])
    sp_items = evidence_index.get("entra-service-principal", [])

    # Map client IDs to display names
    sp_names: dict[str, str] = {}
    for sp in sp_items:
        sd = sp.get("Data", {})
        sp_names[sd.get("AppId", "")] = sd.get("DisplayName", "unknown")
        sp_names[sd.get("Id", "")] = sd.get("DisplayName", "unknown")

    for item in grants:
        d = item.get("Data", {})
        client_id = d.get("ClientId", d.get("clientId", ""))
        consent_type = d.get("ConsentType", d.get("consentType", ""))
        scope = d.get("Scope", d.get("scope", ""))

        if not scope:
            continue

        granted_scopes = {s.strip() for s in scope.split()}
        dangerous = granted_scopes & _DANGEROUS_SCOPES
        app_name = sp_names.get(client_id, client_id or "unknown")

        if len(dangerous) >= 2:
            paths.append(ap_path(
                path_type="consent_abuse",
                subtype="over_consented_app",
                chain=(
                    f"App '{app_name}' has {len(dangerous)} dangerous "
                    f"delegated permissions ({', '.join(sorted(dangerous))}). "
                    f"Consent type: {consent_type}. An attacker compromising this "
                    f"app can read/write mail, files, directory objects, or "
                    f"role assignments."
                ),
                risk_score=85,
                severity="high",
                principal_name=app_name,
                principal_id=client_id,
                roles=sorted(dangerous),
                mitre_technique="T1098.003",
                mitre_tactic="Persistence",
                remediation="Review and reduce delegated permissions; revoke admin consent for unnecessary scopes; require admin consent workflow.",
                ms_learn_url="https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests",
                chain_nodes=[
                    {"type": "application", "label": app_name},
                    {"type": "permission", "label": f"{len(dangerous)} dangerous scopes"},
                    {"type": "action", "label": consent_type},
                    {"type": "impact", "label": "Mail/Files/Dir access"},
                ],
            ))
        elif dangerous and consent_type == "AllPrincipals":
            paths.append(ap_path(
                path_type="consent_abuse",
                subtype="admin_consent_dangerous_scope",
                chain=(
                    f"App '{app_name}' has admin-consented (AllPrincipals) "
                    f"permission {', '.join(sorted(dangerous))}. This scope "
                    f"applies to ALL users in the tenant."
                ),
                risk_score=78,
                severity="high",
                principal_name=app_name,
                principal_id=client_id,
                roles=sorted(dangerous),
                mitre_technique="T1098.003",
                mitre_tactic="Persistence",
                remediation="Convert admin consent to user-specific consent where possible; monitor usage.",
                ms_learn_url="https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow",
                chain_nodes=[
                    {"type": "application", "label": app_name},
                    {"type": "config", "label": "Admin consent (AllPrincipals)"},
                    {"type": "permission", "label": list(dangerous)[0]},
                    {"type": "impact", "label": "Tenant-wide scope"},
                ],
            ))

    return paths
