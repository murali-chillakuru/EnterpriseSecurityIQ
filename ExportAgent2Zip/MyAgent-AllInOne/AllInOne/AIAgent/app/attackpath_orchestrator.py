"""
Attack Path Detection — Orchestrator.

Self-contained evidence collection via ARG + Microsoft Graph,
followed by evaluator invocation across all 3 phases and
report generation.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from app.auth import ComplianceCredentials
from app.query_evaluators.arg_queries import query_resource_graph
from app.collectors.base import paginate_graph

# ── Evaluators ───────────────────────────────────────────────────────────
from app.attackpath_evaluators.privilege_escalation import analyze_privilege_escalation
from app.attackpath_evaluators.lateral_movement import analyze_lateral_movement
from app.attackpath_evaluators.exposed_resources import analyze_exposed_resources
from app.attackpath_evaluators.credential_chain import analyze_credential_chains
from app.attackpath_evaluators.ca_bypass import analyze_ca_bypass
from app.attackpath_evaluators.network_pivot import analyze_network_pivot
from app.attackpath_evaluators.pim_escalation import analyze_pim_escalation
from app.attackpath_evaluators.compromised_identity import analyze_compromised_identity
from app.attackpath_evaluators.consent_abuse import analyze_consent_abuse
from app.attackpath_evaluators.custom_role_escalation import analyze_custom_role_escalation
from app.attackpath_evaluators.data_exposure import analyze_data_exposure
from app.attackpath_evaluators.ai_attack_surface import analyze_ai_attack_surface
from app.attackpath_evaluators.cross_tenant import analyze_cross_tenant
from app.attackpath_evaluators.scoring import compute_risk_summary, filter_by_severity

log = logging.getLogger("attackpath")


# ═════════════════════════════════════════════════════════════════════════
# Evidence record helpers
# ═════════════════════════════════════════════════════════════════════════

def _norm(record: dict) -> dict:
    """Flatten nested properties.xxx keys into PascalCase Data keys."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        if k.startswith("properties_") or k.startswith("properties."):
            clean = k.split(".", 1)[-1] if "." in k else k.split("_", 1)[-1]
            parts = clean.replace("_", ".").split(".")
            pascal = "".join(p.capitalize() for p in parts)
            out[pascal] = v
        else:
            out[k] = v
    return out


def _ev(etype: str, record: dict) -> dict:
    return {
        "EvidenceType": etype,
        "Data": _norm(record),
        "ResourceId": record.get("id", ""),
    }


# ═════════════════════════════════════════════════════════════════════════
# Evidence collection
# ═════════════════════════════════════════════════════════════════════════

async def _collect_evidence(creds: ComplianceCredentials) -> dict[str, list[dict]]:
    """Collect all evidence via ARG + Graph.  Returns evidence_index."""
    index: dict[str, list[dict]] = {}
    errors: list[dict] = []
    subs = await creds.list_subscriptions()
    sub_ids = [s["subscription_id"] for s in subs]
    log.info("Subscriptions in scope: %d", len(sub_ids))

    # ── Phase 1: ARG resource queries ────────────────────────────────
    arg_queries: dict[str, tuple[str, int]] = {
        "azure-storage-account": (
            "Resources | where type =~ 'microsoft.storage/storageaccounts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.allowBlobPublicAccess, "
            "properties.publicNetworkAccess, "
            "properties.minimumTlsVersion, "
            "properties.networkAcls, "
            "properties.encryption, "
            "properties.supportsHttpsTrafficOnly, "
            "identity "
            "| order by id asc",
            1000,
        ),
        "azure-sql-server": (
            "Resources | where type =~ 'microsoft.sql/servers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.administrators, "
            "properties.minimalTlsVersion, "
            "properties.privateEndpointConnections "
            "| order by id asc",
            1000,
        ),
        "azure-keyvault": (
            "Resources | where type =~ 'microsoft.keyvault/vaults' "
            "| project id, name, type, location, resourceGroup, "
            "properties.vaultUri, "
            "properties.enableSoftDelete, "
            "properties.enablePurgeProtection, "
            "properties.enableRbacAuthorization, "
            "properties.networkAcls, "
            "properties.privateEndpointConnections "
            "| order by id asc",
            1000,
        ),
        "azure-webapp-config": (
            "Resources | where type =~ 'microsoft.web/sites' "
            "| project id, name, type, location, resourceGroup, kind, "
            "identity, "
            "properties.httpsOnly, "
            "properties.siteConfig "
            "| order by id asc",
            1000,
        ),
        "azure-function-app": (
            "Resources | where type =~ 'microsoft.web/sites' "
            "| where kind contains 'functionapp' "
            "| project id, name, type, location, resourceGroup, kind, "
            "identity, "
            "properties.httpsOnly, "
            "properties.siteConfig "
            "| order by id asc",
            1000,
        ),
        "azure-managed-identity": (
            "Resources | where type =~ 'microsoft.managedidentity/userassignedidentities' "
            "| project id, name, type, location, resourceGroup, "
            "properties.principalId, "
            "properties.clientId "
            "| order by id asc",
            1000,
        ),
        "azure-nsg-rule": (
            "Resources | where type =~ 'microsoft.network/networksecuritygroups' "
            "| mvexpand rules = properties.securityRules "
            "| extend ruleName = rules.name, "
            "direction = tostring(rules.properties.direction), "
            "access = tostring(rules.properties.access), "
            "sourceAddr = tostring(rules.properties.sourceAddressPrefix), "
            "destPort = tostring(rules.properties.destinationPortRange), "
            "priority = toint(rules.properties.priority) "
            "| where direction == 'Inbound' and access == 'Allow' "
            "and (sourceAddr == '*' or sourceAddr == '0.0.0.0/0' or sourceAddr == 'Internet') "
            "| project id, name, resourceGroup, subscriptionId, "
            "ruleName, sourceAddr, destPort, priority "
            "| extend IsAllowAnyInbound = true "
            "| order by id asc",
            1000,
        ),
        "azure-vm-config": (
            "Resources | where type =~ 'microsoft.compute/virtualmachines' "
            "| project id, name, type, location, resourceGroup, "
            "identity, "
            "properties.hardwareProfile.vmSize, "
            "properties.storageProfile.osDisk.osType "
            "| order by id asc",
            1000,
        ),
        "azure-cosmosdb": (
            "Resources | where type =~ 'microsoft.documentdb/databaseaccounts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.disableLocalAuth, "
            "properties.networkAclBypass, "
            "properties.ipRules, "
            "properties.privateEndpointConnections "
            "| order by id asc",
            1000,
        ),
        "azure-containerregistry": (
            "Resources | where type =~ 'microsoft.containerregistry/registries' "
            "| project id, name, type, location, resourceGroup, "
            "properties.adminUserEnabled, "
            "properties.publicNetworkAccess, "
            "properties.networkRuleSet, "
            "properties.encryption, "
            "sku "
            "| order by id asc",
            1000,
        ),
        "azure-aks": (
            "Resources | where type =~ 'microsoft.containerservice/managedclusters' "
            "| project id, name, type, location, resourceGroup, "
            "properties.enableRBAC, "
            "properties.apiServerAccessProfile, "
            "properties.networkProfile, "
            "properties.aadProfile, "
            "identity "
            "| order by id asc",
            1000,
        ),
        "azure-redis-cache": (
            "Resources | where type =~ 'microsoft.cache/redis' "
            "| project id, name, type, location, resourceGroup, "
            "properties.minimumTlsVersion, "
            "properties.enableNonSslPort, "
            "properties.publicNetworkAccess, "
            "sku "
            "| order by id asc",
            1000,
        ),
        "azure-dbforpostgresql": (
            "Resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.network.publicNetworkAccess, "
            "properties.authConfig, "
            "properties.highAvailability "
            "| order by id asc",
            1000,
        ),
        "azure-dbformysql": (
            "Resources | where type =~ 'microsoft.dbformysql/flexibleservers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.network.publicNetworkAccess, "
            "properties.highAvailability "
            "| order by id asc",
            1000,
        ),
        "azure-cognitive-account": (
            "Resources | where type =~ 'microsoft.cognitiveservices/accounts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.networkAcls, "
            "properties.disableLocalAuth, "
            "properties.encryption, "
            "identity "
            "| order by id asc",
            1000,
        ),
        "azure-data-factory": (
            "Resources | where type =~ 'microsoft.datafactory/factories' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.managedVirtualNetwork, "
            "identity "
            "| order by id asc",
            1000,
        ),
        "azure-ai-workspace": (
            "Resources | where type =~ 'microsoft.machinelearningservices/workspaces' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.description, "
            "identity "
            "| order by id asc",
            1000,
        ),
    }

    for etype, (kql, top) in arg_queries.items():
        try:
            rows = await query_resource_graph(creds, kql, sub_ids, top=top)
            index[etype] = [_ev(etype, r) for r in rows]
            if rows:
                log.info("  ARG [%s]: %d resources", etype, len(rows))
        except Exception as exc:
            log.warning("ARG query failed for %s: %s", etype, exc)
            errors.append({"query": etype, "error": str(exc)})
            index.setdefault(etype, [])

    # ── Role assignments + definitions ───────────────────────────────
    try:
        role_kql = (
            "AuthorizationResources "
            "| where type =~ 'microsoft.authorization/roleassignments' "
            "| extend roleDefId = tostring(properties.roleDefinitionId) "
            "| extend principalId = tostring(properties.principalId) "
            "| extend scope = tostring(properties.scope) "
            "| extend principalType = tostring(properties.principalType) "
            "| project id, roleDefId, principalId, scope, principalType "
            "| order by id asc"
        )
        role_rows = await query_resource_graph(creds, role_kql, sub_ids, top=5000)
        roledef_kql = (
            "AuthorizationResources "
            "| where type =~ 'microsoft.authorization/roledefinitions' "
            "| project id, "
            "roleName = tostring(properties.roleName), "
            "roleType = tostring(properties.type), "
            "permissions = properties.permissions "
            "| order by id asc"
        )
        roledef_rows = await query_resource_graph(creds, roledef_kql, sub_ids, top=500)
        roledef_map = {r.get("id", "").lower(): r.get("roleName", "") for r in roledef_rows}

        index["azure-role-assignment"] = []
        for r in role_rows:
            rdi = r.get("roleDefId", "").lower()
            index["azure-role-assignment"].append({
                "EvidenceType": "azure-role-assignment",
                "Data": {
                    "RoleDefinitionName": roledef_map.get(rdi, ""),
                    "Scope": r.get("scope", ""),
                    "PrincipalId": r.get("principalId", ""),
                    "PrincipalType": r.get("principalType", ""),
                },
                "ResourceId": r.get("id", ""),
            })
        log.info("  ARG [role-assignments]: %d assignments, %d definitions",
                 len(role_rows), len(roledef_rows))

        # Also store role definitions for custom-role analysis
        index["azure-role-definition"] = []
        for r in roledef_rows:
            index["azure-role-definition"].append({
                "EvidenceType": "azure-role-definition",
                "Data": {
                    "RoleName": r.get("roleName", ""),
                    "RoleType": r.get("roleType", ""),
                    "Permissions": r.get("permissions", []),
                },
                "ResourceId": r.get("id", ""),
            })
    except Exception as exc:
        log.warning("Role-assignment ARG query failed: %s", exc)
        errors.append({"query": "role-assignments", "error": str(exc)})

    # ── Phase 2: Microsoft Graph queries ─────────────────────────────
    try:
        graph = creds.get_graph_client()
    except Exception as exc:
        log.warning("Graph client not available: %s", exc)
        graph = None

    if graph:
        # Entra role assignments
        try:
            role_members = await paginate_graph(
                graph.directory_roles
            )
            entra_roles: list[dict] = []
            for role_obj in role_members:
                role_name = getattr(role_obj, "display_name", "")
                role_id = getattr(role_obj, "id", "")
                try:
                    members = await paginate_graph(
                        graph.directory_roles.by_directory_role_id(role_id).members
                    )
                    for m in members:
                        entra_roles.append({
                            "EvidenceType": "entra-role-assignment",
                            "Data": {
                                "RoleName": role_name,
                                "RoleDefinitionId": role_id,
                                "PrincipalId": getattr(m, "id", ""),
                                "PrincipalDisplayName": getattr(m, "display_name", ""),
                                "AssignmentType": "permanent",
                            },
                            "ResourceId": getattr(m, "id", ""),
                        })
                except Exception:
                    pass  # member enumeration may fail for some roles
            index["entra-role-assignment"] = entra_roles
            log.info("  Graph [entra-role-assignment]: %d assignments", len(entra_roles))
        except Exception as exc:
            log.warning("Entra role collection failed: %s", exc)
            errors.append({"query": "entra-role-assignment", "error": str(exc)})

        # Service principals + applications
        try:
            sps = await paginate_graph(graph.service_principals)
            index["entra-service-principal"] = []
            for sp in sps:
                creds_list = list(getattr(sp, "key_credentials", []) or []) + \
                             list(getattr(sp, "password_credentials", []) or [])
                now = datetime.now(timezone.utc)
                has_expired = any(
                    getattr(c, "end_date_time", None) and getattr(c, "end_date_time") < now
                    for c in creds_list
                )
                has_expiring = any(
                    getattr(c, "end_date_time", None)
                    and now < getattr(c, "end_date_time")
                    and (getattr(c, "end_date_time") - now).days <= 30
                    for c in creds_list
                )
                index["entra-service-principal"].append({
                    "EvidenceType": "entra-service-principal",
                    "Data": {
                        "DisplayName": getattr(sp, "display_name", ""),
                        "AppId": getattr(sp, "app_id", ""),
                        "Id": getattr(sp, "id", ""),
                        "HasExpiredCredentials": has_expired,
                        "HasExpiringCredentials": has_expiring,
                        "TotalCredentials": len(creds_list),
                    },
                    "ResourceId": getattr(sp, "id", ""),
                })
            log.info("  Graph [entra-service-principal]: %d", len(sps))
        except Exception as exc:
            log.warning("SP collection failed: %s", exc)
            errors.append({"query": "entra-service-principal", "error": str(exc)})

        # Conditional Access policies
        try:
            from app.collectors.entra.conditional_access import collect_entra_conditional_access
            ca_ev = await collect_entra_conditional_access(creds)
            index["entra-conditional-access-policy"] = ca_ev
            log.info("  Graph [entra-ca]: %d policies", len(ca_ev))
        except Exception as exc:
            log.warning("CA policy collection failed: %s", exc)
            errors.append({"query": "entra-ca", "error": str(exc)})

        # Phase 2 Identity: PIM eligible assignments
        try:
            pim_raw = await paginate_graph(
                graph.role_management.directory.role_eligibility_schedule_instances
            )
            pim_items: list[dict] = []
            for p in pim_raw:
                role_def_id = getattr(p, "role_definition_id", "")
                # Resolve role name from Entra role defs
                pim_items.append({
                    "EvidenceType": "entra-pim-eligible-assignment",
                    "Data": {
                        "PrincipalId": getattr(p, "principal_id", ""),
                        "RoleDefinitionId": role_def_id,
                        "RoleName": "",  # resolved below
                        "PrincipalDisplayName": "",
                        "StartDateTime": str(getattr(p, "start_date_time", "")),
                        "EndDateTime": str(getattr(p, "end_date_time", "")),
                    },
                    "ResourceId": getattr(p, "id", ""),
                })
            # Resolve role names via role definitions
            try:
                entra_role_defs = await paginate_graph(
                    graph.role_management.directory.role_definitions
                )
                rd_map = {
                    getattr(rd, "id", ""): getattr(rd, "display_name", "")
                    for rd in entra_role_defs
                }
                index["entra-directory-role-definition"] = [
                    {
                        "EvidenceType": "entra-directory-role-definition",
                        "Data": {
                            "Id": getattr(rd, "id", ""),
                            "DisplayName": getattr(rd, "display_name", ""),
                            "IsBuiltIn": getattr(rd, "is_built_in", True),
                        },
                        "ResourceId": getattr(rd, "id", ""),
                    }
                    for rd in entra_role_defs
                ]
                for pi in pim_items:
                    pi["Data"]["RoleName"] = rd_map.get(
                        pi["Data"]["RoleDefinitionId"], ""
                    )
            except Exception:
                pass
            index["entra-pim-eligible-assignment"] = pim_items
            log.info("  Graph [entra-pim-eligible]: %d", len(pim_items))
        except Exception as exc:
            log.warning("PIM collection failed: %s", exc)
            errors.append({"query": "entra-pim-eligible", "error": str(exc)})

        # Risky users (Identity Protection)
        try:
            risky = await paginate_graph(
                graph.identity_protection.risky_users
            )
            index["entra-risky-user"] = [
                {
                    "EvidenceType": "entra-risky-user",
                    "Data": {
                        "Id": getattr(u, "id", ""),
                        "UserDisplayName": getattr(u, "user_display_name", ""),
                        "RiskLevel": getattr(u, "risk_level", ""),
                        "RiskState": getattr(u, "risk_state", ""),
                        "RiskLastUpdatedDateTime": str(getattr(u, "risk_last_updated_date_time", "")),
                    },
                    "ResourceId": getattr(u, "id", ""),
                }
                for u in risky
            ]
            log.info("  Graph [entra-risky-user]: %d", len(risky))
        except Exception as exc:
            log.warning("Risky-user collection failed: %s", exc)
            errors.append({"query": "entra-risky-user", "error": str(exc)})

        # OAuth2 permission grants
        try:
            grants = await paginate_graph(graph.oauth2_permission_grants)
            index["entra-oauth2-grant"] = [
                {
                    "EvidenceType": "entra-oauth2-grant",
                    "Data": {
                        "ClientId": getattr(g, "client_id", ""),
                        "ConsentType": getattr(g, "consent_type", ""),
                        "Scope": getattr(g, "scope", ""),
                        "PrincipalId": getattr(g, "principal_id", ""),
                        "ResourceId": getattr(g, "resource_id", ""),
                    },
                    "ResourceId": getattr(g, "id", ""),
                }
                for g in grants
            ]
            log.info("  Graph [entra-oauth2-grant]: %d", len(grants))
        except Exception as exc:
            log.warning("OAuth2 grant collection failed: %s", exc)
            errors.append({"query": "entra-oauth2-grant", "error": str(exc)})

        # Entra applications (app registrations, separate from SPs)
        try:
            apps = await paginate_graph(graph.applications)
            index["entra-application"] = [
                {
                    "EvidenceType": "entra-application",
                    "Data": {
                        "DisplayName": getattr(a, "display_name", ""),
                        "AppId": getattr(a, "app_id", ""),
                        "Id": getattr(a, "id", ""),
                        "SignInAudience": getattr(a, "sign_in_audience", ""),
                        "RequiredResourceAccess": len(getattr(a, "required_resource_access", []) or []),
                    },
                    "ResourceId": getattr(a, "id", ""),
                }
                for a in apps
            ]
            log.info("  Graph [entra-application]: %d", len(apps))
        except Exception as exc:
            log.warning("Application collection failed: %s", exc)
            errors.append({"query": "entra-application", "error": str(exc)})

        # Cross-tenant access settings
        try:
            policy = await graph.policies.cross_tenant_access_policy.get()  # noqa: F841
            partners_raw = await paginate_graph(
                graph.policies.cross_tenant_access_policy.partners
            )
            partner_list = []
            for pt in partners_raw:
                partner_list.append({
                    "EvidenceType": "entra-cross-tenant-access",
                    "Data": {
                        "TenantId": getattr(pt, "tenant_id", ""),
                        "InboundTrust": str(getattr(pt, "inbound_trust", None)),
                        "B2bCollaboration": str(getattr(pt, "b2b_collaboration_inbound", None)),
                        "B2bDirectConnect": str(getattr(pt, "b2b_direct_connect_inbound", None)),
                    },
                    "ResourceId": getattr(pt, "tenant_id", ""),
                })
            index["entra-cross-tenant-access"] = partner_list
            log.info("  Graph [entra-cross-tenant-access]: %d partners", len(partner_list))
        except Exception as exc:
            log.warning("Cross-tenant access collection failed: %s", exc)
            errors.append({"query": "entra-cross-tenant-access", "error": str(exc)})

        # SharePoint sharing links (sites with external sharing)
        try:
            sites = await paginate_graph(graph.sites)
            spo_items = []
            for site in sites:
                spo_items.append({
                    "EvidenceType": "spo-sharing-links",
                    "Data": {
                        "SiteUrl": getattr(site, "web_url", ""),
                        "DisplayName": getattr(site, "display_name", ""),
                        "SiteId": getattr(site, "id", ""),
                    },
                    "ResourceId": getattr(site, "id", ""),
                })
            index["spo-sharing-links"] = spo_items
            log.info("  Graph [spo-sharing-links]: %d sites", len(spo_items))
        except Exception as exc:
            log.warning("SPO sharing collection failed: %s", exc)
            errors.append({"query": "spo-sharing-links", "error": str(exc)})

    # ── Phase 3: Additional ARG queries for AI workloads ─────────────
    ai_arg_queries: dict[str, tuple[str, int]] = {
        "azure-ai-compute": (
            "Resources | where type =~ 'microsoft.machinelearningservices/workspaces/computes' "
            "| project id, name, type, location, resourceGroup, "
            "properties.computeType, "
            "properties.properties.sshSettings, "
            "properties.properties.subnet, "
            "properties.provisioningState "
            "| order by id asc",
            1000,
        ),
        "foundry-agent-application": (
            "Resources | where type =~ 'microsoft.machinelearningservices/workspaces' "
            "| where kind =~ 'hub' or kind =~ 'project' "
            "| project id, name, type, kind, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.description, "
            "identity "
            "| order by id asc",
            1000,
        ),
    }
    for etype, (kql, top) in ai_arg_queries.items():
        try:
            rows = await query_resource_graph(creds, kql, sub_ids, top=top)
            index[etype] = [_ev(etype, r) for r in rows]
            if rows:
                log.info("  ARG [%s]: %d resources", etype, len(rows))
        except Exception as exc:
            log.warning("ARG query failed for %s: %s", etype, exc)
            errors.append({"query": etype, "error": str(exc)})
            index.setdefault(etype, [])

    # Ensure all expected keys exist
    for key in (
        "azure-role-assignment", "azure-role-definition",
        "entra-role-assignment", "entra-service-principal",
        "entra-application", "entra-conditional-access-policy",
        "entra-pim-eligible-assignment", "entra-risky-user",
        "entra-oauth2-grant", "entra-directory-role-definition",
        "entra-cross-tenant-access", "spo-sharing-links",
        "azure-ai-compute", "foundry-agent-application",
    ):
        index.setdefault(key, [])

    index["_collection_errors"] = errors
    return index


# ═════════════════════════════════════════════════════════════════════════
# Pre-built principal→roles map (shared across evaluators)
# ═════════════════════════════════════════════════════════════════════════

def _build_principal_roles(index: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Build principalId → [{Role, Scope, PrincipalType}] mapping."""
    principal_roles: dict[str, list[dict]] = {}
    for item in index.get("azure-role-assignment", []):
        d = item.get("Data", {})
        pid = d.get("PrincipalId", d.get("principalId", ""))
        role = d.get("RoleDefinitionName", d.get("roleDefinitionName", ""))
        scope = d.get("Scope", d.get("scope", ""))
        ptype = d.get("PrincipalType", d.get("principalType", ""))
        if pid:
            principal_roles.setdefault(pid, []).append({
                "Role": role, "Scope": scope, "PrincipalType": ptype,
            })
    return principal_roles


# ═════════════════════════════════════════════════════════════════════════
# Main orchestrator entry point
# ═════════════════════════════════════════════════════════════════════════

async def run_attack_path_assessment(
    tenant_id: str,
    *,
    evidence_path: str | None = None,
    output_dir: str | None = None,
    min_severity: str = "informational",
    previous_run: str | None = None,
    formats: list[str] | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run the full attack-path assessment pipeline.

    1. Collect evidence (or load from *evidence_path*).
    2. Run all evaluators.
    3. Score and summarize.
    4. Generate reports.
    5. Write outputs to disk.

    Returns the full assessment result dict.
    """
    formats = formats or ["json", "html", "excel"]
    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    if not output_dir:
        output_dir = os.path.join("output", ts, "Attack-Path-Detection")
    os.makedirs(output_dir, exist_ok=True)
    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # ── Step 1: Evidence ─────────────────────────────────────────────
    if evidence_path:
        log.info("Loading evidence from %s", evidence_path)
        with open(evidence_path, "r", encoding="utf-8") as f:
            evidence_index = json.load(f)
    else:
        log.info("Collecting evidence for tenant %s …", tenant_id)
        creds = ComplianceCredentials(tenant_id=tenant_id)
        evidence_index = await _collect_evidence(creds)

    # Save raw evidence
    for etype, items in evidence_index.items():
        if etype.startswith("_"):
            continue
        raw_file = os.path.join(raw_dir, f"{etype}.json")
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, default=str)

    # ── Step 2: Run all evaluators ───────────────────────────────────
    principal_roles = _build_principal_roles(evidence_index)
    all_paths: list[dict] = []

    evaluators = [
        ("privilege_escalation", lambda: analyze_privilege_escalation(evidence_index)),
        ("lateral_movement", lambda: analyze_lateral_movement(evidence_index, principal_roles)),
        ("exposed_resources", lambda: analyze_exposed_resources(evidence_index)),
        ("credential_chain", lambda: analyze_credential_chains(evidence_index, principal_roles)),
        ("ca_bypass", lambda: analyze_ca_bypass(evidence_index)),
        ("network_pivot", lambda: analyze_network_pivot(evidence_index, principal_roles)),
        ("pim_escalation", lambda: analyze_pim_escalation(evidence_index)),
        ("compromised_identity", lambda: analyze_compromised_identity(evidence_index)),
        ("consent_abuse", lambda: analyze_consent_abuse(evidence_index)),
        ("custom_role_escalation", lambda: analyze_custom_role_escalation(evidence_index)),
        ("data_exposure", lambda: analyze_data_exposure(evidence_index)),
        ("ai_attack_surface", lambda: analyze_ai_attack_surface(evidence_index)),
        ("cross_tenant", lambda: analyze_cross_tenant(evidence_index)),
    ]

    for name, evaluator in evaluators:
        try:
            results = evaluator()
            all_paths.extend(results)
            if results:
                log.info("  [%s]: %d paths", name, len(results))
        except Exception as exc:
            log.error("Evaluator %s failed: %s", name, exc)

    # ── Step 3: Filter + Score ───────────────────────────────────────
    all_paths = filter_by_severity(all_paths, min_severity)

    previous_paths = None
    if previous_run:
        try:
            with open(previous_run, "r", encoding="utf-8") as f:
                prev_data = json.load(f)
                previous_paths = prev_data.get("paths", prev_data.get("Paths", []))
        except Exception as exc:
            log.warning("Could not load previous run: %s", exc)

    summary = compute_risk_summary(all_paths, previous_paths=previous_paths)

    assessment = {
        "AssessmentTimestamp": datetime.now(timezone.utc).isoformat(),
        "TenantId": tenant_id,
        "Summary": summary,
        "Paths": all_paths,
        "Evidence": {
            k: v for k, v in evidence_index.items() if not k.startswith("_")
        },
        "EvidenceTypes": {
            k: len(v) for k, v in evidence_index.items() if not k.startswith("_")
        },
        "CollectionErrors": evidence_index.get("_collection_errors", []),
    }

    # ── Step 4: Write outputs ────────────────────────────────────────
    # JSON (exclude raw evidence to keep file size manageable)
    if "json" in formats:
        json_path = os.path.join(output_dir, "attack-path-assessment.json")
        json_payload = {k: v for k, v in assessment.items() if k != "Evidence"}
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, default=str)
        log.info("JSON report: %s", json_path)

    # HTML
    if "html" in formats:
        try:
            from app.attackpath_reports.attack_path_report import generate_html_report
            html_path = os.path.join(output_dir, "attack-path-report.html")
            html_content = generate_html_report(assessment)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            log.info("HTML report: %s", html_path)
        except Exception as exc:
            log.error("HTML report generation failed: %s", exc)

    # Excel
    if "excel" in formats:
        try:
            from app.attackpath_reports.attack_path_excel import generate_excel_report
            xlsx_path = os.path.join(output_dir, "attack-path-report.xlsx")
            generate_excel_report(assessment, xlsx_path)
            log.info("Excel report: %s", xlsx_path)
        except Exception as exc:
            log.error("Excel report generation failed: %s", exc)

    # Executive brief
    try:
        from app.attackpath_reports.executive_brief import generate_executive_brief
        brief_path = os.path.join(output_dir, "attack-path-executive-brief.html")
        brief = generate_executive_brief(assessment)
        with open(brief_path, "w", encoding="utf-8") as f:
            f.write(brief)
        log.info("Executive brief: %s", brief_path)
    except Exception as exc:
        log.error("Executive brief generation failed: %s", exc)

    if not quiet:
        _print_console_summary(summary)

    return assessment


def _print_console_summary(summary: dict) -> None:
    """Print a compact summary to the console."""
    print("\n" + "=" * 60)
    print("  ATTACK PATH DETECTION — SUMMARY")
    print("=" * 60)
    print(f"  Total Paths Detected : {summary['TotalPaths']}")
    print(f"  Overall Risk Score   : {summary['OverallRiskScore']}/100")
    print(f"  Overall Severity     : {summary['OverallSeverity'].upper()}")
    print()
    sc = summary["SeverityCounts"]
    print(f"  Critical: {sc['critical']}  |  High: {sc['high']}  |  "
          f"Medium: {sc['medium']}  |  Low: {sc['low']}")
    print()
    if summary.get("Trend"):
        t = summary["Trend"]
        print(f"  Trend: {t['Direction'].upper()} "
              f"(+{t['NewPaths']} new, -{t['ResolvedPaths']} resolved)")
        print()
    if summary["Top5Paths"]:
        print("  Top Paths:")
        for i, p in enumerate(summary["Top5Paths"], 1):
            print(f"    {i}. [{p['Severity'].upper():8s}] Score={p['RiskScore']} | {p['Type']}")
            chain = p.get("Chain", "")
            if len(chain) > 100:
                chain = chain[:100] + "…"
            print(f"       {chain}")
    print("=" * 60 + "\n")
