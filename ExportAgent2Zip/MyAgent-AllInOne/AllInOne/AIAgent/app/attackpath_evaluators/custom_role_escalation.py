"""
Attack Path Detection — Custom Role Escalation evaluator.

Phase 2 Identity: Custom RBAC roles with dangerous permission combinations
that can be exploited for privilege escalation.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

# Dangerous Azure permission actions (Microsoft.Authorization write = self-escalation)
_DANGEROUS_ACTIONS = {
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/*/write",
    "*/write",
    "*",
}

# Data-plane escalation actions
_DATA_PLANE_DANGEROUS = {
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
    "Microsoft.KeyVault/vaults/secrets/*",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
}


def analyze_custom_role_escalation(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect custom roles with dangerous permission combinations."""
    paths: list[dict] = []

    role_defs = evidence_index.get("azure-role-definition", [])
    if not role_defs:
        role_defs = evidence_index.get("entra-directory-role-definition", [])

    for item in role_defs:
        d = item.get("Data", {})
        role_name = d.get("RoleName", d.get("DisplayName", d.get("roleName", "unknown")))
        role_type = d.get("RoleType", d.get("roleType", ""))
        if role_type not in ("CustomRole", "Custom"):
            continue

        permissions = d.get("Permissions", d.get("permissions", []))
        all_actions: set[str] = set()
        for perm_block in permissions:
            if isinstance(perm_block, dict):
                for action in perm_block.get("actions", []):
                    all_actions.add(action)
                for action in perm_block.get("dataActions", []):
                    all_actions.add(action)

        dangerous_found = all_actions & _DANGEROUS_ACTIONS
        data_dangerous_found = all_actions & _DATA_PLANE_DANGEROUS

        if dangerous_found:
            paths.append(ap_path(
                path_type="custom_role_escalation",
                subtype="authorization_write",
                chain=(
                    f"Custom role '{role_name}' includes {', '.join(sorted(dangerous_found))} "
                    f"permission(s). A principal assigned this role can grant themselves "
                    f"any built-in role, achieving full control-plane escalation."
                ),
                risk_score=94,
                severity="critical",
                role_name=role_name,
                roles=sorted(dangerous_found),
                mitre_technique="T1098",
                mitre_tactic="Privilege Escalation",
                remediation="Remove authorization write permissions from custom roles; use built-in roles with least-privilege.",
                ms_learn_url="https://learn.microsoft.com/azure/role-based-access-control/custom-roles-best-practice",
                chain_nodes=[
                    {"type": "role", "label": role_name},
                    {"type": "permission", "label": list(dangerous_found)[0]},
                    {"type": "action", "label": "Grant any role"},
                    {"type": "impact", "label": "Control-plane escalation"},
                ],
            ))

        if data_dangerous_found and not dangerous_found:
            paths.append(ap_path(
                path_type="custom_role_escalation",
                subtype="data_plane_access",
                chain=(
                    f"Custom role '{role_name}' includes data-plane permissions: "
                    f"{', '.join(sorted(data_dangerous_found))}. "
                    f"Can read secrets or data from storage without control-plane "
                    f"visibility in activity logs."
                ),
                risk_score=75,
                severity="medium",
                role_name=role_name,
                roles=sorted(data_dangerous_found),
                mitre_technique="T1552.001",
                mitre_tactic="Credential Access",
                remediation="Audit data-plane permissions in custom roles; ensure logging is enabled.",
                ms_learn_url="https://learn.microsoft.com/azure/role-based-access-control/custom-roles",
                chain_nodes=[
                    {"type": "role", "label": role_name},
                    {"type": "permission", "label": list(data_dangerous_found)[0]},
                    {"type": "impact", "label": "Data-plane access"},
                ],
            ))

    return paths
