"""
Attack Path Detection — PIM Escalation evaluator.

Phase 2 Identity: PIM-eligible assignments that create hidden privilege paths.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path

_HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Security Administrator",
}


def analyze_pim_escalation(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect PIM-eligible assignments that create hidden privilege paths.

    Flags:
    - Users eligible for multiple high-privilege roles (multi-role hop).
    - Eligible roles with no activation approval required.
    """
    paths: list[dict] = []

    pim_items = evidence_index.get("entra-pim-eligible-assignment", [])

    # Group PIM-eligible by principal
    eligible_by_principal: dict[str, list[dict]] = {}
    for item in pim_items:
        d = item.get("Data", {})
        pid = d.get("PrincipalId", "")
        if pid:
            eligible_by_principal.setdefault(pid, []).append(d)

    # Detect multi-role PIM escalation
    for pid, assignments in eligible_by_principal.items():
        high_roles = [a for a in assignments
                      if a.get("RoleName", "") in _HIGH_PRIV_ROLES]
        if len(high_roles) >= 2:
            principal_name = high_roles[0].get("PrincipalDisplayName", "unknown")
            role_names = [a.get("RoleName", "") for a in high_roles]
            paths.append(ap_path(
                path_type="pim_escalation",
                subtype="multi_role_eligible",
                chain=(
                    f"'{principal_name}' is PIM-eligible for {len(high_roles)} "
                    f"high-privilege roles ({', '.join(role_names)}). An attacker "
                    f"compromising this account can activate multiple roles "
                    f"simultaneously for broad tenant control."
                ),
                risk_score=90,
                severity="critical",
                principal_id=pid,
                principal_name=principal_name,
                roles=role_names,
                mitre_technique="T1078.004",
                mitre_tactic="Privilege Escalation",
                remediation="Distribute PIM-eligible roles across separate accounts; enable activation approval for critical roles.",
                ms_learn_url="https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings",
                chain_nodes=[
                    {"type": "identity", "label": principal_name},
                    {"type": "permission", "label": f"PIM: {len(high_roles)} roles"},
                    {"type": "privilege", "label": role_names[0]},
                    {"type": "impact", "label": "Multi-role activation"},
                ],
            ))

    # Detect eligible Global Admin without approval
    for item in pim_items:
        d = item.get("Data", {})
        if d.get("RoleName") == "Global Administrator":
            approval = d.get("RequiresApproval", True)
            if not approval:
                paths.append(ap_path(
                    path_type="pim_escalation",
                    subtype="ga_no_approval",
                    chain=(
                        f"'{d.get('PrincipalDisplayName', 'unknown')}' can activate "
                        f"Global Administrator via PIM WITHOUT approval. Self-service "
                        f"activation of the highest privilege role is a critical risk."
                    ),
                    risk_score=95,
                    severity="critical",
                    principal_id=d.get("PrincipalId", ""),
                    principal_name=d.get("PrincipalDisplayName", "unknown"),
                    role_name="Global Administrator",
                    mitre_technique="T1078.004",
                    mitre_tactic="Privilege Escalation",
                    remediation="Enable activation approval for Global Administrator with at least 2 approvers.",
                    ms_learn_url="https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings",
                    chain_nodes=[
                        {"type": "identity", "label": d.get("PrincipalDisplayName", "unknown")},
                        {"type": "config", "label": "No approval required"},
                        {"type": "privilege", "label": "Global Administrator"},
                        {"type": "impact", "label": "Self-service GA activation"},
                    ],
                ))

    return paths
