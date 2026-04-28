"""
Attack Path Detection — Compromised Identity evaluator.

Phase 2 Identity: Risky users with active privileged roles.
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
    "User Administrator",
}


def analyze_compromised_identity(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect Entra risky users that hold active privileged roles.

    If Identity Protection flags a user as at-risk AND they hold a
    privileged Entra role, the blast radius is extremely high.
    """
    paths: list[dict] = []

    risky_users = evidence_index.get("entra-risky-user", [])
    entra_roles = evidence_index.get("entra-role-assignment", [])

    # Build set of users with active privileged roles
    privileged_users: dict[str, list[str]] = {}
    for item in entra_roles:
        d = item.get("Data", {})
        pid = d.get("PrincipalId", "")
        role = d.get("RoleName", d.get("DisplayName", ""))
        if pid and role in _HIGH_PRIV_ROLES:
            privileged_users.setdefault(pid, []).append(role)

    for item in risky_users:
        d = item.get("Data", {})
        user_id = d.get("Id", d.get("id", ""))
        display = d.get("UserDisplayName", d.get("userDisplayName", "unknown"))
        risk_level = d.get("RiskLevel", d.get("riskLevel", "unknown"))
        risk_state = d.get("RiskState", d.get("riskState", ""))

        if risk_state == "dismissed":
            continue

        user_priv_roles = privileged_users.get(user_id, [])
        if user_priv_roles:
            score = 97 if risk_level == "high" else (90 if risk_level == "medium" else 80)
            paths.append(ap_path(
                path_type="compromised_identity",
                subtype="risky_user_privileged",
                chain=(
                    f"User '{display}' is flagged as {risk_level}-risk by "
                    f"Identity Protection AND holds {len(user_priv_roles)} "
                    f"privileged role(s): {', '.join(user_priv_roles)}. "
                    f"This user may already be compromised with full admin access."
                ),
                risk_score=score,
                severity="critical" if risk_level in ("high", "medium") else "high",
                principal_id=user_id,
                principal_name=display,
                roles=user_priv_roles,
                mitre_technique="T1078",
                mitre_tactic="Initial Access",
                remediation="Investigate immediately; force password reset; revoke sessions; review sign-in logs.",
                ms_learn_url="https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk",
                chain_nodes=[
                    {"type": "identity", "label": display},
                    {"type": "exposure", "label": f"{risk_level}-risk user"},
                    {"type": "privilege", "label": user_priv_roles[0]},
                    {"type": "impact", "label": f"{len(user_priv_roles)} priv roles"},
                ],
            ))

    return paths
