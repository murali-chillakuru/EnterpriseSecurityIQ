"""
Attack Path Detection — Cross-Tenant evaluator.

Phase 3 Identity: Open B2B inbound trust that allows external
tenants to access internal resources.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path


def analyze_cross_tenant(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect open B2B inbound trust and cross-tenant resource access."""
    paths: list[dict] = []

    # ── B2B Inbound Trust settings ───────────────────────────────────
    xt_items = evidence_index.get("entra-cross-tenant-access", [])
    for item in xt_items:
        d = item.get("Data", {})
        tenant_id = d.get("TenantId", d.get("tenantId", ""))
        tenant_name = d.get("DisplayName", d.get("displayName", tenant_id or "unknown"))
        inbound_trust = d.get("InboundTrust", d.get("inboundTrust", {}))

        if isinstance(inbound_trust, dict):
            allow_mfa = inbound_trust.get("IsMfaAccepted", inbound_trust.get("isMfaAccepted", False))
            allow_device = inbound_trust.get("IsCompliantDeviceAccepted",
                          inbound_trust.get("isCompliantDeviceAccepted", False))
            if allow_mfa and allow_device:
                paths.append(ap_path(
                    path_type="cross_tenant",
                    subtype="open_b2b_inbound",
                    chain=(
                        f"Tenant '{tenant_name}' ({tenant_id}) has inbound trust "
                        f"that accepts MFA AND device compliance from the external "
                        f"tenant. A compromised account in that tenant can access "
                        f"internal resources as a guest with trusted claims."
                    ),
                    risk_score=78,
                    severity="high",
                    source=f"External tenant: {tenant_name}",
                    target="Internal resources (via B2B inbound trust)",
                    mitre_technique="T1199",
                    mitre_tactic="Initial Access",
                    remediation="Restrict inbound trust to specific applications; don't accept external MFA/device claims unless required.",
                    ms_learn_url="https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration",
                    chain_nodes=[
                        {"type": "external", "label": f"Tenant: {tenant_name[:20]}"},
                        {"type": "config", "label": "Inbound trust (MFA+Device)"},
                        {"type": "impact", "label": "Internal resources"},
                    ],
                ))

    # ── External guest users with active roles (from role assignments) ──
    role_assigns = evidence_index.get("azure-role-assignment", [])

    for item in role_assigns:
        d = item.get("Data", {})
        ptype = d.get("PrincipalType", d.get("principalType", ""))
        if ptype in ("ForeignGroup", "Guest"):
            role = d.get("RoleDefinitionName", d.get("roleDefinitionName", ""))
            scope = d.get("Scope", d.get("scope", ""))
            paths.append(ap_path(
                path_type="cross_tenant",
                subtype="external_principal_azure_role",
                chain=(
                    f"External {ptype} principal has '{role}' role at scope "
                    f"'{scope}'. Cross-tenant principals with Azure resource "
                    f"access create external attack surface."
                ),
                risk_score=72,
                severity="medium",
                principal_type=ptype,
                role_name=role,
                target=scope,
                mitre_technique="T1199",
                mitre_tactic="Initial Access",
                remediation="Review external principal role assignments; remove unnecessary access; use access reviews.",
                ms_learn_url="https://learn.microsoft.com/entra/id-governance/manage-guest-access-with-access-reviews",
                chain_nodes=[
                    {"type": "external", "label": ptype},
                    {"type": "permission", "label": role},
                    {"type": "resource", "label": scope[:30]},
                ],
            ))

    return paths
