"""
Asset Management Domain Evaluator
Controls: CM-8, PM-5 (NIST), PCI 2.4, ISO A.5.9, CIS asset management.
Evaluates asset inventory completeness, classification tagging,
authorized software policies, and application inventory.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_asset_management(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_asset_inventory": _check_asset_inventory,
        "check_classification_tagging": _check_classification_tagging,
        "check_authorized_software_policy": _check_authorized_software,
        "check_application_inventory": _check_application_inventory,
        "check_iot_asset_inventory": _check_iot_asset_inventory,
        "check_container_workload_inventory": _check_container_workload_inventory,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", ""),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="asset_management", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _check_asset_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Verify resource inventory is comprehensive and discoverable."""
    findings = []
    resources = idx.get("azure-resource", [])
    resource_groups = idx.get("azure-resource-group", [])
    managed_ids = idx.get("azure-managed-identity", [])

    if not resources:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Azure resource inventory collected.",
                   recommendation="Ensure resource inventory collection is enabled in PostureIQ configuration.")]

    # Inventory completeness: resources in groups
    findings.append(_f(cid, ctrl, Status.COMPLIANT,
                       f"Asset inventory: {len(resources)} resources across {len(resource_groups)} resource groups."))

    # Check for managed identities (identity inventory component)
    if managed_ids:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(managed_ids)} managed identities inventoried."))

    # Resource diversity check — a healthy inventory has multiple resource types
    resource_types = {r.get("Data", {}).get("ResourceType", "").lower() for r in resources}
    if len(resource_types) < 3 and len(resources) > 10:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Low resource type diversity ({len(resource_types)} types for {len(resources)} resources) — inventory may be incomplete.",
                          recommendation="Review resource collection scope to ensure all resource types are discovered."))

    return findings


def _check_classification_tagging(cid, ctrl, evidence, idx, thresholds=None):
    """Verify resources have classification tags for data sensitivity."""
    findings = []
    resources = idx.get("azure-resource", [])
    resource_groups = idx.get("azure-resource-group", [])
    all_items = resources + resource_groups

    if not all_items:
        return [_f(cid, ctrl, Status.COMPLIANT, "No resources to evaluate for classification tagging.")]

    tagged = sum(1 for r in all_items if r.get("Data", {}).get("Tags"))
    pct = (tagged / len(all_items)) * 100 if all_items else 0

    if pct < 50:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Resource tagging {pct:.0f}% (<50%) — data classification is inadequate.",
                          recommendation="Implement mandatory tagging policy with tags: environment, data-classification, owner, cost-center."))
    elif pct < 80:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Resource tagging {pct:.0f}% (50-79%) — data classification needs improvement.",
                          recommendation="Increase tagging coverage to ≥80%. Use Azure Policy to enforce mandatory tags."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Resource tagging {pct:.0f}% (≥80%) — classification tagging meets threshold."))

    # Check for specific classification tags
    classification_keys = {"data-classification", "dataclassification", "classification",
                           "sensitivity", "data_classification", "confidentiality"}
    classified = sum(1 for r in all_items
                     if any(k.lower() in classification_keys
                            for k in (r.get("Data", {}).get("Tags") or {}).keys()))
    if classified == 0 and len(all_items) > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No resources have data classification tags (e.g., 'data-classification', 'sensitivity').",
                          recommendation="Add data classification tags to identify resources handling sensitive data."))

    return findings


def _check_authorized_software(cid, ctrl, evidence, idx, thresholds=None):
    """Verify policies control authorized resource types and services."""
    findings = []
    policies = idx.get("azure-policy-assignment", [])

    if not policies:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Azure policies assigned for authorized resource control.",
                   recommendation="Assign 'Allowed resource types' or 'Not allowed resource types' policies.")]

    # Check for resource type restriction policies
    restrict_keywords = ("allowed resource", "not allowed resource", "allowed location",
                         "restrict", "deny", "whitelist", "allowlist")
    restricting = [p for p in policies
                   if any(k in str(p.get("Data", {}).get("DisplayName", "")).lower()
                          for k in restrict_keywords)]

    if not restricting:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No policies restricting resource types or locations found.",
                          recommendation="Deploy 'Allowed resource types' and 'Allowed locations' policies."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(restricting)} policies controlling authorized resources/locations."))

    # Initiatives (policy sets) indicate mature governance
    initiatives = [p for p in policies if p.get("Data", {}).get("IsPolicySet")]
    if initiatives:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(initiatives)} policy initiative(s) for comprehensive resource governance."))

    return findings


def _check_application_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Verify application and service principal inventory is maintained."""
    findings = []
    apps = idx.get("entra-application", [])
    sps = idx.get("entra-service-principal", [])

    if not apps and not sps:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No application or service principal inventory available.",
                   recommendation="Enable Entra ID application collection to maintain software asset inventory.")]

    if apps:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(apps)} Entra ID application registrations inventoried."))

    if sps:
        # Check for service principals without owners (orphaned)
        no_owner_count = sum(1 for sp in sps
                             if not sp.get("Data", {}).get("Owners")
                             and not sp.get("Data", {}).get("OwnerCount"))
        if no_owner_count > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{no_owner_count} service principals without assigned owners.",
                              recommendation="Assign owners to all service principals for accountability and lifecycle management."))
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(sps)} service principals inventoried."))

    return findings


# ---------------------------------------------------------------------------
# v55 — IoT / Digital Twins Asset Inventory
# ---------------------------------------------------------------------------
def _check_iot_asset_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Check IoT Hub, Digital Twins, and IoT Central inventory is maintained."""
    findings = []
    resources = idx.get("azure-resource", [])

    iot_hubs = [r for r in resources
                if "iothub" in (r.get("Data", {}).get("ResourceType") or "").lower()]
    digital_twins = [r for r in resources
                     if "digitaltwins" in (r.get("Data", {}).get("ResourceType") or "").lower()]
    iot_central = [r for r in resources
                   if "iotcentral" in (r.get("Data", {}).get("ResourceType") or "").lower()]

    total_iot = len(iot_hubs) + len(digital_twins) + len(iot_central)

    if total_iot > 0:
        # IoT Hubs without Defender
        for item in iot_hubs:
            d = item.get("Data", {})
            name = d.get("Name", "unknown")
            defender = d.get("DefenderEnabled") or d.get("SecuritySolutionEnabled")
            if defender is False:
                r = dict(
                    resource_id=d.get("ResourceId", ""),
                    resource_name=name,
                    resource_type="Microsoft.Devices/IotHubs",
                )
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"IoT Hub '{name}' does not have Defender for IoT enabled.",
                                  recommendation="Enable Defender for IoT to discover and inventory IoT devices.", **r))

        if not findings:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"IoT asset inventory: {len(iot_hubs)} IoT Hub(s), "
                              f"{len(digital_twins)} Digital Twin(s), {len(iot_central)} IoT Central app(s)."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "No IoT/Digital Twins resources to inventory."))

    return findings


# ---------------------------------------------------------------------------
# v55 — Container Workload Inventory (ACI, ARO, Container Apps)
# ---------------------------------------------------------------------------
def _check_container_workload_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Inventory container workloads across ACI, ARO, and Container Apps."""
    findings = []
    resources = idx.get("azure-resource", [])
    aks = idx.get("azure-aks-cluster", [])
    container_apps = idx.get("azure-container-app", [])

    aci = [r for r in resources
           if "containerinstance" in (r.get("Data", {}).get("ResourceType") or "").lower()
           or "containergroup" in (r.get("Data", {}).get("ResourceType") or "").lower()]
    aro = [r for r in resources
           if "openshiftcluster" in (r.get("Data", {}).get("ResourceType") or "").lower()]

    total = len(aks) + len(container_apps) + len(aci) + len(aro)

    if total > 0:
        parts = []
        if aks:
            parts.append(f"{len(aks)} AKS cluster(s)")
        if container_apps:
            parts.append(f"{len(container_apps)} Container App(s)")
        if aci:
            parts.append(f"{len(aci)} Container Instance(s)")
        if aro:
            parts.append(f"{len(aro)} ARO cluster(s)")
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Container workload inventory: {', '.join(parts)}."))

        # ACI security check — public IP without network restrictions
        for item in aci:
            d = item.get("Data", {})
            name = d.get("Name", "unknown")
            ip_type = d.get("IpAddressType") or d.get("IpAddress", {}).get("type", "")
            if str(ip_type).lower() == "public":
                r = dict(resource_id=d.get("ResourceId", ""), resource_name=name,
                         resource_type="Microsoft.ContainerInstance/containerGroups")
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Container Instance '{name}' has a public IP address.",
                                  recommendation="Deploy container instances in a VNet for network isolation.", **r))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "No container workloads to inventory."))

    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for asset management control ({len(evidence)} items).")]
