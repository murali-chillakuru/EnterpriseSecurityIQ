"""
Attack Path Detection — AI Attack Surface evaluator.

Phase 3 AI/Foundry: AI workspaces, compute instances, model endpoints,
and Foundry agents that may be publicly exposed or misconfigured.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path


def analyze_ai_attack_surface(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect AI/ML workspaces, compute, and agent misconfigurations."""
    paths: list[dict] = []

    # ── AI/ML Workspaces with public access ──────────────────────────
    ai_workspaces = evidence_index.get("azure-ai-workspace", [])
    for item in ai_workspaces:
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        has_identity = bool(d.get("Identity", d.get("identity", {})))

        if str(public).lower() in ("enabled", "true", ""):
            score = 85 if has_identity else 75
            paths.append(ap_path(
                path_type="ai_attack_surface",
                subtype="workspace_public",
                chain=(
                    f"AI/ML Workspace '{name}' has public network access"
                    f"{' and a managed identity' if has_identity else ''}. "
                    f"An attacker can reach the workspace API, submit training jobs, "
                    f"or access stored models and datasets."
                ),
                risk_score=score,
                severity="high",
                resource_type="AI/ML Workspace",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public network access",
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                remediation="Disable public network access; use private endpoints; enable workspace-level RBAC.",
                ms_learn_url="https://learn.microsoft.com/azure/machine-learning/how-to-configure-private-link",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"AI Workspace '{name}'"},
                    {"type": "exposure", "label": "Public network access"},
                ],
            ))

    # ── AI Compute instances without auto-shutdown ───────────────────
    ai_compute = evidence_index.get("azure-ai-compute", [])
    for item in ai_compute:
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        comp_type = d.get("ComputeType", d.get("properties_computeType", ""))
        public_ip = d.get("PublicIpAddress", d.get("properties_publicIpAddress", ""))
        ssh_enabled = d.get("SshEnabled", d.get("properties_sshPublicAccess", ""))

        if public_ip or str(ssh_enabled).lower() in ("enabled", "true"):
            paths.append(ap_path(
                path_type="ai_attack_surface",
                subtype="compute_exposed",
                chain=(
                    f"AI compute instance '{name}' (type: {comp_type}) has "
                    f"{'public IP' if public_ip else ''}"
                    f"{' and ' if public_ip and ssh_enabled else ''}"
                    f"{'SSH access enabled' if str(ssh_enabled).lower() in ('enabled', 'true') else ''}. "
                    f"Direct access to training compute can lead to data exfiltration "
                    f"or model poisoning."
                ),
                risk_score=80,
                severity="high",
                resource_type="AI Compute Instance",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public IP / SSH access",
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                remediation="Disable SSH public access; remove public IP; use Azure Bastion for access.",
                ms_learn_url="https://learn.microsoft.com/azure/machine-learning/how-to-secure-compute-instance",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "compute", "label": f"AI Compute '{name}'"},
                    {"type": "exposure", "label": "Public IP / SSH"},
                ],
            ))

    # ── Foundry Agent Applications with no auth / public endpoint ────
    agents = evidence_index.get("foundry-agent-application", [])
    for item in agents:
        d = item.get("Data", {})
        name = d.get("Name", d.get("DisplayName", "unknown"))
        auth_type = d.get("AuthType", d.get("authType", ""))
        is_public = d.get("IsPublic", d.get("isPublic", False))

        if auth_type in ("none", "") or is_public:
            paths.append(ap_path(
                path_type="ai_attack_surface",
                subtype="agent_unauthenticated",
                chain=(
                    f"Foundry agent '{name}' has "
                    f"{'no authentication' if auth_type in ('none', '') else 'public access'}. "
                    f"An attacker can invoke the agent to extract data, run prompts "
                    f"against the model, or abuse tool integrations."
                ),
                risk_score=88,
                severity="high",
                resource_type="Foundry Agent",
                resource_name=name,
                exposure="No auth / public endpoint",
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                remediation="Enable Entra authentication; restrict access to authorized principals only.",
                ms_learn_url="https://learn.microsoft.com/azure/ai-foundry/how-to/develop/create-hub-project-sdk",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "application", "label": f"Agent '{name}'"},
                    {"type": "exposure", "label": "No auth / public"},
                ],
            ))

    return paths
