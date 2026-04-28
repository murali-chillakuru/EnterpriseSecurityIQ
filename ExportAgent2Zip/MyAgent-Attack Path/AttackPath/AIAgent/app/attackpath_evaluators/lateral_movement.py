"""
Attack Path Detection — Lateral Movement evaluator.

Phase 2: Managed-identity lateral movement chains.
Phase 6: App/Function → Managed Identity → Privileged Resource chains.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

_ESCALATION_ROLES = {
    "Owner",
    "User Access Administrator",
    "Contributor",
    "Key Vault Administrator",
    "Storage Blob Data Owner",
    "Virtual Machine Contributor",
}


def analyze_lateral_movement(
    evidence_index: dict[str, list[dict]],
    principal_roles: dict[str, list[dict]],
) -> list[dict]:
    """Detect MI-based lateral movement and App→MI→Resource chains.

    *principal_roles* is a pre-built mapping of principalId → [{Role, Scope, PrincipalType}].
    """
    paths: list[dict] = []

    # ── Phase 2: MI lateral movement ─────────────────────────────────
    mi_items = evidence_index.get("azure-managed-identity", [])
    for item in mi_items:
        d = item.get("Data", {})
        mi_name = d.get("Name", d.get("DisplayName", "unknown"))
        mi_id = d.get("PrincipalId", d.get("principalId", ""))
        mi_roles = principal_roles.get(mi_id, [])
        priv_roles = [r for r in mi_roles if r["Role"] in _ESCALATION_ROLES]

        if priv_roles:
            resources = d.get("AssociatedResources", [])
            for res in resources[:5]:
                paths.append(ap_path(
                    path_type="lateral_movement",
                    chain=(
                        f"MI '{mi_name}' has '{priv_roles[0]['Role']}' → "
                        f"compromising host gives attacker privileged Azure access."
                    ),
                    risk_score=85,
                    severity="high",
                    source=f"Managed Identity '{mi_name}'",
                    target=res.get("ResourceId", res) if isinstance(res, dict) else str(res),
                    roles=[r["Role"] for r in priv_roles],
                    mitre_technique="T1550.001",
                    mitre_tactic="Lateral Movement",
                    remediation="Apply least-privilege roles to managed identities; scope to specific resources, not subscriptions.",
                    ms_learn_url="https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations",
                    chain_nodes=[
                        {"type": "identity", "label": f"MI '{mi_name}'"},
                        {"type": "permission", "label": priv_roles[0]["Role"]},
                        {"type": "resource", "label": str(res)[:40]},
                    ],
                ))

    # ── Phase 6: App/Function → MI → Privileged Resource ────────────
    webapps = evidence_index.get("azure-webapp-config", [])
    func_apps = evidence_index.get("azure-function-app", [])
    compute_apps = webapps + func_apps
    for app in compute_apps:
        d = app.get("Data", {})
        app_name = d.get("Name", d.get("SiteName", "unknown"))
        app_type = "Function App" if app.get("EvidenceType") == "azure-function-app" else "Web App"
        mi_principal = ""
        identity = d.get("Identity", d.get("identity", {}))
        if isinstance(identity, dict):
            mi_principal = identity.get("PrincipalId", identity.get("principalId", ""))
        if not mi_principal:
            mi_principal = d.get("ManagedIdentityPrincipalId", d.get("identityPrincipalId", ""))
        if mi_principal:
            mi_priv_roles = [r for r in principal_roles.get(mi_principal, [])
                             if r["Role"] in _ESCALATION_ROLES]
            if mi_priv_roles:
                paths.append(ap_path(
                    path_type="lateral_movement",
                    subtype="app_mi_to_resource",
                    chain=(
                        f"{app_type} '{app_name}' has system-assigned MI → MI holds "
                        f"'{mi_priv_roles[0]['Role']}' at '{mi_priv_roles[0]['Scope']}'. "
                        f"Exploiting the app (e.g., SSRF, RCE) grants the attacker "
                        f"privileged Azure access via the MI's token endpoint."
                    ),
                    risk_score=87,
                    severity="high",
                    source=f"{app_type} '{app_name}'",
                    target=f"{mi_priv_roles[0]['Role']} at {mi_priv_roles[0]['Scope']}",
                    roles=[r["Role"] for r in mi_priv_roles],
                    mitre_technique="T1550.001",
                    mitre_tactic="Lateral Movement",
                    remediation="Apply least-privilege roles scoped to specific resources; enable private endpoints for the app.",
                    ms_learn_url="https://learn.microsoft.com/azure/app-service/overview-managed-identity",
                    chain_nodes=[
                        {"type": "compute", "label": f"{app_type} '{app_name}'"},
                        {"type": "identity", "label": "System MI"},
                        {"type": "permission", "label": mi_priv_roles[0]["Role"]},
                        {"type": "resource", "label": mi_priv_roles[0]["Scope"][:30]},
                    ],
                ))

    return paths
