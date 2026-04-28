"""
Attack Path Detection — Credential Chain evaluator.

Phase 5: Key Vault → Identity → Resource credential chains.
Phase 8: Expired/expiring credentials on privileged Service Principals.
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

_KV_READ_ROLES = {
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Key Vault Secrets User",
    "Key Vault Crypto Officer",
    "Key Vault Certificates Officer",
    "Key Vault Reader",
    "Owner",
    "Contributor",
}


def analyze_credential_chains(
    evidence_index: dict[str, list[dict]],
    principal_roles: dict[str, list[dict]],
) -> list[dict]:
    """Detect Key Vault → identity → resource chains and weak SP credentials."""
    paths: list[dict] = []

    # ── Phase 5: Key Vault → Identity → Resource ────────────────────
    kv_items = evidence_index.get("azure-keyvault", [])
    for kv in kv_items:
        d = kv.get("Data", {})
        vault_name = d.get("VaultName", d.get("Name", d.get("name", "unknown")))
        vault_id = kv.get("ResourceId", d.get("id", ""))
        for pid, roles in principal_roles.items():
            kv_roles = [r for r in roles
                        if r["Role"] in _KV_READ_ROLES
                        and (vault_id in r.get("Scope", "") or r.get("Scope", "").count("/") <= 4)]
            other_priv = [r for r in roles
                         if r["Role"] in _ESCALATION_ROLES and r["Role"] not in _KV_READ_ROLES]
            if kv_roles and other_priv:
                paths.append(ap_path(
                    path_type="credential_chain",
                    subtype="keyvault_to_resource",
                    chain=(
                        f"Principal has '{kv_roles[0]['Role']}' on Key Vault '{vault_name}' → "
                        f"can read secrets/keys/certs → also holds '{other_priv[0]['Role']}' at "
                        f"'{other_priv[0]['Scope']}'. Compromising this identity exposes both "
                        f"vault secrets AND privileged resource access."
                    ),
                    risk_score=88,
                    severity="high",
                    principal_id=pid,
                    principal_type=kv_roles[0].get("PrincipalType", "Unknown"),
                    source=f"Key Vault '{vault_name}'",
                    target=f"{other_priv[0]['Role']} at {other_priv[0]['Scope']}",
                    roles=[r["Role"] for r in kv_roles + other_priv],
                    mitre_technique="T1552.001",
                    mitre_tactic="Credential Access",
                    remediation="Separate KV reader and resource admin roles; use different identities for secret access vs. resource management.",
                    ms_learn_url="https://learn.microsoft.com/azure/key-vault/general/best-practices",
                    chain_nodes=[
                        {"type": "resource", "label": f"Key Vault '{vault_name}'"},
                        {"type": "identity", "label": f"Principal {pid[:8]}…"},
                        {"type": "permission", "label": kv_roles[0]["Role"]},
                        {"type": "privilege", "label": other_priv[0]["Role"]},
                        {"type": "resource", "label": other_priv[0]["Scope"][:30]},
                    ],
                ))

    # ── Phase 8: Expired/expiring creds on privileged SPs ────────────
    sp_items = evidence_index.get("entra-service-principal", [])
    app_items = evidence_index.get("entra-application", [])
    for item in app_items + sp_items:
        d = item.get("Data", {})
        display = d.get("DisplayName", "unknown")
        obj_id = d.get("ObjectId", d.get("Id", d.get("id", "")))
        has_expired = d.get("HasExpiredCredentials", False)
        has_expiring = d.get("HasExpiringCredentials", False)
        total_creds = d.get("TotalCredentials", 0)
        if (has_expired or has_expiring) and total_creds > 0:
            sp_roles = principal_roles.get(obj_id, [])
            priv = [r for r in sp_roles if r["Role"] in _ESCALATION_ROLES]
            if priv:
                status = "expired" if has_expired else "expiring within 30 days"
                paths.append(ap_path(
                    path_type="credential_chain",
                    subtype="weak_credential_privileged_sp",
                    chain=(
                        f"'{display}' has {status} credentials AND holds "
                        f"'{priv[0]['Role']}' at '{priv[0]['Scope']}'. Credential "
                        f"mismanagement on a privileged SP creates a window for "
                        f"unauthorized access or loss of automation continuity."
                    ),
                    risk_score=82 if has_expired else 75,
                    severity="high" if has_expired else "medium",
                    principal_id=obj_id,
                    principal_name=display,
                    credential_status=status,
                    roles=[r["Role"] for r in priv],
                    mitre_technique="T1078.004",
                    mitre_tactic="Persistence",
                    remediation="Rotate credentials; prefer managed identity over SP credentials; set expiration alerts.",
                    ms_learn_url="https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview",
                    chain_nodes=[
                        {"type": "application", "label": display},
                        {"type": "config", "label": f"Creds: {status}"},
                        {"type": "permission", "label": priv[0]["Role"]},
                        {"type": "impact", "label": "Privileged SP at risk"},
                    ],
                ))

    return paths
