"""
Attack Path Detection — Conditional Access Bypass evaluator.

Phase 7: Privileged Entra roles without MFA enforcement.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

# Privileged Entra roles that should always require MFA
_PRIVILEGED_ENTRA_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Security Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "Intune Administrator",
}


def analyze_ca_bypass(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect privileged Entra roles without MFA via Conditional Access."""
    paths: list[dict] = []

    ca_policies = evidence_index.get("entra-conditional-access-policy", [])
    entra_roles = evidence_index.get("entra-role-assignment", [])

    # Identify roles protected by at least one MFA-enforcing CA policy
    enabled_ca = [p for p in ca_policies
                  if p.get("Data", {}).get("State") == "enabled"
                  and p.get("Data", {}).get("RequiresMFA")]
    mfa_protected_roles: set[str] = set()
    targets_all_users = False
    for pol in enabled_ca:
        pd = pol.get("Data", {})
        if pd.get("TargetsAllUsers"):
            targets_all_users = True
        for role_id in pd.get("IncludeRoles", []):
            mfa_protected_roles.add(role_id)

    if targets_all_users:
        return paths  # All users have MFA — no bypass paths

    for item in entra_roles:
        d = item.get("Data", {})
        role_name = d.get("RoleName", d.get("DisplayName", ""))
        role_id = d.get("RoleDefinitionId", d.get("RoleId", ""))
        principal_name = d.get("PrincipalDisplayName", d.get("MemberName", "unknown"))

        if role_name in _PRIVILEGED_ENTRA_ROLES:
            if role_id not in mfa_protected_roles and "All" not in mfa_protected_roles:
                paths.append(ap_path(
                    path_type="ca_bypass",
                    subtype="privileged_role_no_mfa",
                    chain=(
                        f"'{principal_name}' holds '{role_name}' but no Conditional Access "
                        f"policy enforces MFA for this role. An attacker with stolen "
                        f"credentials can sign in without a second factor."
                    ),
                    risk_score=92,
                    severity="critical",
                    principal_name=principal_name,
                    principal_id=d.get("PrincipalId", ""),
                    role_name=role_name,
                    mitre_technique="T1078",
                    mitre_tactic="Defense Evasion",
                    remediation="Create a CA policy targeting this role that requires MFA and compliant device.",
                    ms_learn_url="https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
                    chain_nodes=[
                        {"type": "identity", "label": principal_name},
                        {"type": "config", "label": "No MFA policy"},
                        {"type": "privilege", "label": role_name},
                        {"type": "impact", "label": "Credential-only access"},
                    ],
                ))

    return paths
