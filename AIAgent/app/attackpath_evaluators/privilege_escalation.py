"""
Attack Path Detection — Privilege Escalation evaluator.

Phase 1: RBAC-based privilege escalation chains.
Phase 4: Entra permanent Global Administrator assignments.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

# Roles that grant broad control-plane access
_ESCALATION_ROLES = {
    "Owner",
    "User Access Administrator",
    "Contributor",
    "Key Vault Administrator",
    "Storage Blob Data Owner",
    "Virtual Machine Contributor",
}

# Roles that can create/modify role assignments (self-escalation)
_IAM_WRITE_ROLES = {
    "Owner",
    "User Access Administrator",
}


def analyze_privilege_escalation(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect RBAC and Entra privilege escalation chains.

    Returns a list of attack-path dicts.
    """
    paths: list[dict] = []

    # ── Phase 1: RBAC self-escalation ────────────────────────────────
    rbac_items = evidence_index.get("azure-role-assignment", [])
    principal_roles: dict[str, list[dict]] = {}
    for item in rbac_items:
        d = item.get("Data", {})
        principal = d.get("PrincipalId", "") or d.get("principalId", "")
        role = d.get("RoleDefinitionName", "") or d.get("roleDefinitionName", "")
        scope = d.get("Scope", "") or d.get("scope", "")
        ptype = d.get("PrincipalType", "") or d.get("principalType", "")
        if principal:
            principal_roles.setdefault(principal, []).append({
                "Role": role, "Scope": scope, "PrincipalType": ptype,
            })

    for pid, roles in principal_roles.items():
        iam_write = [r for r in roles if r["Role"] in _IAM_WRITE_ROLES]
        if iam_write:
            escalation_targets = [r for r in roles if r["Role"] in _ESCALATION_ROLES]
            if len(escalation_targets) > 1:
                paths.append(ap_path(
                    path_type="privilege_escalation",
                    chain=(
                        f"Has '{iam_write[0]['Role']}' at scope '{iam_write[0]['Scope']}' → "
                        f"can grant self any role. Currently holds {len(escalation_targets)} "
                        f"privileged roles."
                    ),
                    risk_score=95,
                    severity="critical",
                    principal_id=pid,
                    principal_type=iam_write[0].get("PrincipalType", "Unknown"),
                    roles=[r["Role"] for r in escalation_targets],
                    mitre_technique="T1078.004",
                    mitre_tactic="Privilege Escalation",
                    remediation="Remove standing IAM-write roles; use PIM for just-in-time elevation with approval workflows.",
                    ms_learn_url="https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure",
                    chain_nodes=[
                        {"type": "identity", "label": f"Principal {pid[:8]}…"},
                        {"type": "permission", "label": iam_write[0]["Role"]},
                        {"type": "privilege", "label": f"{len(escalation_targets)} priv roles"},
                        {"type": "impact", "label": "Self-grant any role"},
                    ],
                ))

    # ── Phase 4: Entra permanent Global Admin ────────────────────────
    entra_roles = evidence_index.get("entra-role-assignment", [])
    for item in entra_roles:
        d = item.get("Data", {})
        role_name = d.get("RoleName", d.get("DisplayName", ""))
        principal_name = d.get("PrincipalDisplayName", d.get("MemberName", "unknown"))
        is_eligible = d.get("AssignmentType", "").lower() == "eligible"
        is_permanent = not is_eligible and not d.get("EndDateTime")

        if role_name == "Global Administrator" and is_permanent:
            paths.append(ap_path(
                path_type="privilege_escalation",
                subtype="permanent_global_admin",
                chain=(
                    f"'{principal_name}' has permanent Global Administrator "
                    f"assignment (not PIM-eligible). Compromise of this account "
                    f"gives full tenant control."
                ),
                risk_score=100,
                severity="critical",
                principal_id=d.get("PrincipalId", ""),
                principal_name=principal_name,
                mitre_technique="T1078.004",
                mitre_tactic="Privilege Escalation",
                remediation="Convert to PIM-eligible assignment with time-limited activation and MFA + approval.",
                ms_learn_url="https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user",
                chain_nodes=[
                    {"type": "identity", "label": principal_name},
                    {"type": "privilege", "label": "Global Administrator"},
                    {"type": "impact", "label": "Full tenant control"},
                ],
            ))
    return paths
