"""
Attack Path Detection — Network Pivot evaluator.

Phase 9: Internet-exposed VMs with privileged managed identities.
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


def analyze_network_pivot(
    evidence_index: dict[str, list[dict]],
    principal_roles: dict[str, list[dict]],
) -> list[dict]:
    """Detect network pivot: internet-exposed VMs with privileged MIs."""
    paths: list[dict] = []

    nsg_rules = evidence_index.get("azure-nsg-rule", [])
    vm_items = evidence_index.get("azure-vm-config", [])

    # Find NSGs that allow any inbound from Internet
    open_nsg_subs: set[str] = set()
    for rule in nsg_rules:
        rd = rule.get("Data", {})
        if rd.get("IsAllowAnyInbound"):
            sub_id = rd.get("SubscriptionId", "")
            if sub_id:
                open_nsg_subs.add(sub_id)

    for vm in vm_items:
        vd = vm.get("Data", {})
        vm_name = vd.get("Name", vd.get("VMName", "unknown"))
        vm_sub = vd.get("SubscriptionId", "")
        mi_principal = ""
        vm_mi = vd.get("Identity", {})
        if isinstance(vm_mi, dict):
            mi_principal = vm_mi.get("PrincipalId", "")
        if not mi_principal:
            mi_principal = vd.get("ManagedIdentityPrincipalId", "")
        if mi_principal and vm_sub in open_nsg_subs:
            vm_priv = [r for r in principal_roles.get(mi_principal, [])
                       if r["Role"] in _ESCALATION_ROLES]
            if vm_priv:
                paths.append(ap_path(
                    path_type="network_pivot",
                    subtype="internet_exposed_vm_privileged_mi",
                    chain=(
                        f"VM '{vm_name}' is in a subscription with Internet-exposed NSG "
                        f"rules AND its managed identity holds '{vm_priv[0]['Role']}' at "
                        f"'{vm_priv[0]['Scope']}'. An attacker exploiting this VM can "
                        f"request an MI token from IMDS (169.254.169.254) and pivot to "
                        f"privileged Azure resource access."
                    ),
                    risk_score=93,
                    severity="critical",
                    source=f"Internet → VM '{vm_name}'",
                    target=f"{vm_priv[0]['Role']} at {vm_priv[0]['Scope']}",
                    roles=[r["Role"] for r in vm_priv],
                    mitre_technique="T1021",
                    mitre_tactic="Lateral Movement",
                    remediation="Restrict NSG inbound rules; remove standing privileged roles from VM MIs; use JIT VM access.",
                    ms_learn_url="https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-usage",
                    chain_nodes=[
                        {"type": "external", "label": "Internet"},
                        {"type": "network", "label": "Open NSG"},
                        {"type": "compute", "label": f"VM '{vm_name}'"},
                        {"type": "identity", "label": "Managed Identity"},
                        {"type": "permission", "label": vm_priv[0]["Role"]},
                    ],
                ))

    return paths
