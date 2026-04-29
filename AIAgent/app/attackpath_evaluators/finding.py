"""
Attack Path Detection — Finding helper & constants.

Shared by all attackpath_evaluators modules.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

# ── Severity weights ────────────────────────────────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

# Stable UUID namespace for deterministic path IDs
AP_FINDING_NS = uuid.UUID("f1a2b3c4-d5e6-47f8-a9b0-c1d2e3f4a5b6")


def ap_path(
    path_type: str,
    chain: str,
    risk_score: int,
    severity: str,
    *,
    subtype: str = "",
    principal_id: str = "",
    principal_name: str = "",
    principal_type: str = "",
    source: str = "",
    target: str = "",
    resource_type: str = "",
    resource_name: str = "",
    resource_id: str = "",
    exposure: str = "",
    roles: list[str] | None = None,
    credential_status: str = "",
    role_name: str = "",
    mitre_technique: str = "",
    mitre_tactic: str = "",
    remediation: str = "",
    ms_learn_url: str = "",
    chain_nodes: list[dict] | None = None,
    remediation_cli: str = "",
    remediation_powershell: str = "",
    remediation_portal: str = "",
    compliance_frameworks: dict[str, list[str]] | None = None,
) -> dict:
    """Create a standardised attack-path dict.

    The path ID is deterministic: derived from type, subtype, principal,
    source, and target so identical inputs produce the same ID.
    """
    fingerprint = f"{path_type}|{subtype}|{principal_id}|{source}|{target}|{resource_id}"
    path_id = str(uuid.uuid5(AP_FINDING_NS, fingerprint))

    result: dict = {
        "AttackPathId": path_id,
        "Type": path_type,
        "Chain": chain,
        "RiskScore": risk_score,
        "Severity": severity,
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }
    if subtype:
        result["Subtype"] = subtype
    if principal_id:
        result["PrincipalId"] = principal_id
    if principal_name:
        result["PrincipalName"] = principal_name
    if principal_type:
        result["PrincipalType"] = principal_type
    if source:
        result["Source"] = source
    if target:
        result["Target"] = target
    if resource_type:
        result["ResourceType"] = resource_type
    if resource_name:
        result["ResourceName"] = resource_name
    if resource_id:
        result["ResourceId"] = resource_id
    if exposure:
        result["Exposure"] = exposure
    if roles:
        result["Roles"] = roles
    if credential_status:
        result["CredentialStatus"] = credential_status
    if role_name:
        result["RoleName"] = role_name
    if mitre_technique:
        result["MitreTechnique"] = mitre_technique
    if mitre_tactic:
        result["MitreTactic"] = mitre_tactic
    if remediation:
        result["Remediation"] = remediation
    if ms_learn_url:
        result["MSLearnUrl"] = ms_learn_url
    if chain_nodes:
        result["ChainNodes"] = chain_nodes
    if remediation_cli:
        result["RemediationCLI"] = remediation_cli
    if remediation_powershell:
        result["RemediationPowerShell"] = remediation_powershell
    if remediation_portal:
        result["RemediationPortal"] = remediation_portal
    if compliance_frameworks:
        result["ComplianceFrameworks"] = compliance_frameworks
    return result
