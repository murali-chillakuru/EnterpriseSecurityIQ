"""
Business Continuity Domain Evaluator
Controls: CP-2, CP-6, CP-9, CP-10 (NIST), PCI 12.10.1, HIPAA 164.308(a)(7).
Evaluates backup configuration, geo-redundancy, VM availability,
and database resilience for disaster recovery readiness.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_business_continuity(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_backup_configuration": _check_backup_configuration,
        "check_geo_redundancy": _check_geo_redundancy,
        "check_vm_availability": _check_vm_availability,
        "check_database_resilience": _check_database_resilience,
        "check_site_recovery_health": _check_site_recovery_health,
        "check_multi_region_resilience": _check_multi_region_resilience,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", ""),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="business_continuity", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _res(item, rtype=""):
    d = item.get("Data", {})
    ctx = item.get("Context", {})
    return dict(
        resource_id=d.get("ResourceId") or ctx.get("ResourceId") or item.get("ResourceId", ""),
        resource_name=d.get("Name") or d.get("DisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_backup_configuration(cid, ctrl, evidence, idx, thresholds=None):
    """Verify Recovery Services vaults exist with soft-delete and proper configuration."""
    findings = []
    vaults = idx.get("azure-recovery-vault", [])
    vms = idx.get("azure-vm-config", [])
    sql_servers = idx.get("azure-sql-server", [])

    if not vaults:
        resources_needing_backup = len(vms) + len(sql_servers)
        if resources_needing_backup > 0:
            return [_f(cid, ctrl, Status.NON_COMPLIANT,
                       f"No Recovery Services vaults but {resources_needing_backup} resources need backup protection.",
                       recommendation="Deploy Recovery Services vaults and configure backup for VMs and databases.")]
        return [_f(cid, ctrl, Status.COMPLIANT, "No resources requiring backup protection found.")]

    # Soft delete check
    no_soft_delete = [v for v in vaults if not v.get("Data", {}).get("SoftDeleteEnabled")]
    if no_soft_delete:
        vault_names = [v.get("Data", {}).get("Name", "unknown") for v in no_soft_delete[:5]]
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(no_soft_delete)} recovery vault(s) without soft delete: {', '.join(vault_names)}.",
                          recommendation="Enable soft delete on all Recovery Services vaults to prevent accidental data loss."))

    # Immutability check (if available)
    no_immutability = [v for v in vaults
                       if v.get("Data", {}).get("ImmutabilityState") == "Disabled"
                       or (v.get("Data", {}).get("ImmutabilityState") is not None
                           and v.get("Data", {}).get("ImmutabilityState") != "Enabled"
                           and v.get("Data", {}).get("ImmutabilityState") != "Locked")]

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(vaults)} recovery vault(s) configured with soft delete enabled."))

    return findings


def _check_geo_redundancy(cid, ctrl, evidence, idx, thresholds=None):
    """Verify storage accounts and databases use geo-redundant replication."""
    findings = []
    storage = idx.get("azure-storage-account", [])
    cosmos = idx.get("azure-cosmosdb-account", [])

    if storage:
        geo_types = {"Standard_GRS", "Standard_RAGRS", "Standard_GZRS", "Standard_RAGZRS"}
        non_geo = [s for s in storage
                   if s.get("Data", {}).get("ReplicationType") not in geo_types
                   and s.get("Data", {}).get("SkuName") not in geo_types]
        if non_geo:
            names = sorted(s.get("Data", {}).get("Name", "unknown") for s in non_geo[:5])
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(non_geo)} storage account(s) without geo-redundant replication: {', '.join(names)}.",
                              recommendation="Upgrade storage accounts to GRS, RA-GRS, GZRS, or RA-GZRS for geo-redundancy."))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"All {len(storage)} storage accounts use geo-redundant replication."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "No storage accounts to evaluate for geo-redundancy."))

    # Cosmos DB multi-region
    if cosmos:
        single_region = [c for c in cosmos
                         if not c.get("Data", {}).get("EnableMultipleWriteLocations")
                         and (c.get("Data", {}).get("LocationCount", 1) or 1) <= 1]
        if single_region:
            names = sorted(c.get("Data", {}).get("Name", "unknown") for c in single_region[:5])
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(single_region)} Cosmos DB account(s) in single region: {', '.join(names)}.",
                              recommendation="Configure Cosmos DB accounts with multiple regions for geo-redundancy."))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"All {len(cosmos)} Cosmos DB accounts have multi-region replication."))

    return findings


def _check_vm_availability(cid, ctrl, evidence, idx, thresholds=None):
    """Verify VMs use availability zones or availability sets for resilience."""
    findings = []
    vms = idx.get("azure-vm-config", [])

    if not vms:
        return [_f(cid, ctrl, Status.COMPLIANT, "No VMs to evaluate for availability.")]

    no_ha = []
    for vm in vms:
        d = vm.get("Data", {})
        has_zone = d.get("AvailabilityZone") or d.get("Zones")
        has_avset = d.get("AvailabilitySetId") or d.get("AvailabilitySet")
        if not has_zone and not has_avset:
            no_ha.append(vm)

    if no_ha:
        names = sorted(v.get("Data", {}).get("Name", "unknown") for v in no_ha[:5])
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(no_ha)}/{len(vms)} VMs without availability zones or sets: {', '.join(names)}.",
                          recommendation="Deploy VMs in availability zones or availability sets for high availability."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(vms)} VMs deployed with availability zones or sets."))

    return findings


def _check_database_resilience(cid, ctrl, evidence, idx, thresholds=None):
    """Verify databases have resilience features (geo-replication, failover groups)."""
    findings = []
    sql_servers = idx.get("azure-sql-server", [])
    sql_detailed = idx.get("azure-sql-detailed", [])
    db_servers = idx.get("azure-database-server", [])

    if not sql_servers and not db_servers:
        return [_f(cid, ctrl, Status.COMPLIANT, "No database servers to evaluate for resilience.")]

    # SQL Server checks
    if sql_detailed:
        for srv in sql_detailed:
            d = srv.get("Data", {})
            name = d.get("ServerName", "unknown")

            # Check firewall — allow-all indicates potential DR misconfiguration
            if d.get("AllowAllAzureIps"):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"SQL server '{name}' allows all Azure IPs — review network isolation for DR.",
                                  recommendation="Use private endpoints or restrictive firewall rules even for DR configurations."))
    elif sql_servers:
        # Basic SQL server check
        for srv in sql_servers:
            d = srv.get("Data", {})
            name = d.get("Name", "unknown")
            version = d.get("Version", "")
            if version and version < "12.0":
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"SQL server '{name}' version {version} may not support modern HA features.",
                                  recommendation="Upgrade to SQL Server 12.0+ for zone-redundant and geo-replication support."))

    # PostgreSQL/MySQL HA check
    if db_servers:
        for srv in db_servers:
            d = srv.get("Data", {})
            name = d.get("Name", "unknown")
            ha_enabled = d.get("HighAvailability") or d.get("HaEnabled")
            if ha_enabled is False:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Database server '{name}' does not have high availability enabled.",
                                  recommendation="Enable zone-redundant or same-zone high availability for production databases."))

    if not findings:
        total = len(sql_servers) + len(db_servers)
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {total} database server(s) meet resilience requirements."))

    return findings


# ---------------------------------------------------------------------------
# v55 — Site Recovery Replication Health
# ---------------------------------------------------------------------------
def _check_site_recovery_health(cid, ctrl, evidence, idx, thresholds=None):
    """Check Azure Site Recovery replication items for health and RPO compliance."""
    findings = []
    vaults = idx.get("azure-recovery-vault", [])
    sr_items = [r for r in idx.get("azure-resource", [])
                if "replicationprotecteditem" in (r.get("Data", {}).get("ResourceType") or "").lower()
                or "siterecovery" in (r.get("Data", {}).get("ResourceType") or "").lower()]

    if not vaults and not sr_items:
        # Check if there are VMs that should be protected
        vms = idx.get("azure-vm-config", [])
        if len(vms) > 5:
            return [_f(cid, ctrl, Status.NON_COMPLIANT,
                       f"{len(vms)} VMs but no Site Recovery configuration for DR.",
                       recommendation="Deploy Azure Site Recovery for VM disaster recovery to a secondary region.")]
        return [_f(cid, ctrl, Status.COMPLIANT, "No Site Recovery resources to evaluate.")]

    for item in sr_items:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, d.get("ResourceType", "Microsoft.RecoveryServices/vaults/replicationProtectedItems"))
        health = d.get("ReplicationHealth") or d.get("ProtectionState", "")
        if str(health).lower() in ("critical", "warning"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Site Recovery item '{name}' replication health: {health}.",
                              recommendation="Investigate and resolve replication health issues.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Site Recovery health adequate ({len(sr_items)} protected items, {len(vaults)} vaults)."))
    return findings


# ---------------------------------------------------------------------------
# v55 — Multi-Region Resilience
# ---------------------------------------------------------------------------
def _check_multi_region_resilience(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate multi-region deployment patterns for critical resources."""
    findings = []
    resources = idx.get("azure-resource", [])
    webapps = idx.get("azure-webapp-config", [])
    aks_clusters = idx.get("azure-aks-cluster", [])
    front_doors = [r for r in resources
                   if "frontdoor" in (r.get("Data", {}).get("ResourceType") or "").lower()
                   or "trafficmanager" in (r.get("Data", {}).get("ResourceType") or "").lower()]

    # Compute unique regions
    regions: set[str] = set()
    for r in resources:
        loc = r.get("Data", {}).get("Location") or r.get("Data", {}).get("Region", "")
        if loc:
            regions.add(str(loc).lower())

    if len(regions) <= 1 and len(resources) > 10:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"All {len(resources)} resources deployed in a single region ({', '.join(regions) or 'unknown'}).",
                          recommendation="Consider multi-region deployment for disaster recovery and availability."))
    elif len(regions) > 1:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Resources deployed across {len(regions)} region(s): {', '.join(sorted(regions))}."))

    # Global load balancer check
    if len(regions) > 1 and not front_doors:
        findings.append(_f(cid, ctrl, Status.INFO,
                          "Multi-region deployment detected but no Front Door or Traffic Manager for global load balancing.",
                          recommendation="Deploy Azure Front Door or Traffic Manager for cross-region failover."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Multi-region resilience adequate ({len(regions)} region(s))."))
    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for business continuity control ({len(evidence)} items).")]
