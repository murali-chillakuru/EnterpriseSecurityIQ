"""
Attack Path Detection — Exposed High-Value Resources evaluator.

Phase 3: Publicly exposed resources that store sensitive data.
Covers 11 resource types across all assessment domains.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path


def analyze_exposed_resources(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect publicly exposed high-value resources.

    Scans: Storage, SQL, Key Vault, CosmosDB, PostgreSQL, MySQL,
    ACR, AKS, Redis, Cognitive/AI Services, Data Factory.
    """
    paths: list[dict] = []

    # ── Storage Accounts with public blob access ─────────────────────
    for item in evidence_index.get("azure-storage-account", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public_access = d.get("AllowBlobPublicAccess", d.get("PublicNetworkAccess",
                        d.get("properties_allowBlobPublicAccess", "")))
        if str(public_access).lower() in ("true", "enabled"):
            paths.append(ap_path(
                path_type="exposed_high_value",
                chain=f"Storage Account '{name}' has public blob access enabled — "
                      f"anonymous users can enumerate and read containers set to public.",
                risk_score=80,
                severity="high",
                resource_type="Storage Account",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public blob access enabled",
                mitre_technique="T1530",
                mitre_tactic="Collection",
                remediation="Disable public blob access: az storage account update --name <name> --allow-blob-public-access false",
                ms_learn_url="https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"Storage '{name}'"},
                    {"type": "exposure", "label": "Public blob access"},
                ],
            ))

    # ── SQL Servers with public network access ───────────────────────
    for item in evidence_index.get("azure-sql-server", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        if str(public).lower() in ("enabled", "true"):
            paths.append(ap_path(
                path_type="exposed_high_value",
                chain=f"SQL Server '{name}' has public network access enabled — "
                      f"attackers can attempt brute-force or exploit SQL injection from the internet.",
                risk_score=85,
                severity="high",
                resource_type="SQL Server",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public network access enabled",
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                remediation="Disable public network access; use private endpoints: az sql server update --name <name> --public-network-access Disabled",
                ms_learn_url="https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"SQL Server '{name}'"},
                    {"type": "exposure", "label": "Public network access"},
                ],
            ))

    # ── Key Vaults with unrestricted network access ──────────────────
    for item in evidence_index.get("azure-keyvault", []):
        d = item.get("Data", {})
        name = d.get("VaultName", d.get("Name", d.get("name", "unknown")))
        network_rules = d.get("NetworkAcls", d.get("NetworkRuleSet",
                        d.get("properties_networkAcls", {})))
        default_action = ""
        if isinstance(network_rules, dict):
            default_action = network_rules.get("DefaultAction",
                            network_rules.get("defaultAction", ""))
        if str(default_action).lower() == "allow":
            paths.append(ap_path(
                path_type="exposed_high_value",
                chain=f"Key Vault '{name}' has network default action 'Allow' — "
                      f"secrets, keys, and certificates accessible from any network.",
                risk_score=90,
                severity="critical",
                resource_type="Key Vault",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Network default action is Allow (unrestricted)",
                mitre_technique="T1552.001",
                mitre_tactic="Credential Access",
                remediation="Set network default action to Deny; add VNet rules or private endpoints.",
                ms_learn_url="https://learn.microsoft.com/azure/key-vault/general/network-security",
                chain_nodes=[
                    {"type": "external", "label": "Any network"},
                    {"type": "resource", "label": f"Key Vault '{name}'"},
                    {"type": "exposure", "label": "Network Allow all"},
                ],
            ))

    # ── CosmosDB with public access + local auth ─────────────────────
    for item in evidence_index.get("azure-cosmosdb", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        local_auth = d.get("DisableLocalAuth", d.get("properties_disableLocalAuth", ""))
        if str(public).lower() in ("enabled", "true", ""):
            score = 88 if str(local_auth).lower() in ("false", "") else 75
            sev = "high" if score >= 80 else "medium"
            chain = f"Cosmos DB '{name}' has public network access"
            if str(local_auth).lower() in ("false", ""):
                chain += " AND local auth enabled (connection strings work)"
            paths.append(ap_path(
                path_type="exposed_high_value",
                chain=chain + " — attackers with credentials can read/write all data.",
                risk_score=score,
                severity=sev,
                resource_type="Cosmos DB",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public access + local auth",
                mitre_technique="T1530",
                mitre_tactic="Collection",
                remediation="Disable public network access; disable local auth; use Entra RBAC.",
                ms_learn_url="https://learn.microsoft.com/azure/cosmos-db/how-to-setup-rbac",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"Cosmos DB '{name}'"},
                    {"type": "exposure", "label": "Public + local auth"},
                ],
            ))

    # ── PostgreSQL / MySQL with public access ────────────────────────
    for etype in ("azure-dbforpostgresql", "azure-dbformysql"):
        label = "PostgreSQL" if "postgres" in etype else "MySQL"
        for item in evidence_index.get(etype, []):
            d = item.get("Data", {})
            name = d.get("Name", d.get("name", "unknown"))
            public = d.get("PublicNetworkAccess",
                    d.get("properties_network_publicNetworkAccess",
                    d.get("properties_publicNetworkAccess", "")))
            if str(public).lower() in ("enabled", "true"):
                paths.append(ap_path(
                    path_type="exposed_high_value",
                    chain=f"{label} Flexible Server '{name}' has public network access enabled.",
                    risk_score=82,
                    severity="high",
                    resource_type=f"{label} Flexible Server",
                    resource_name=name,
                    resource_id=item.get("ResourceId", d.get("id", "")),
                    exposure="Public network access enabled",
                    mitre_technique="T1190",
                    mitre_tactic="Initial Access",
                    remediation=f"Disable public network access on {label}; use private endpoints.",
                    ms_learn_url="https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-private",
                    chain_nodes=[
                        {"type": "external", "label": "Internet"},
                        {"type": "resource", "label": f"{label} '{name}'"},
                        {"type": "exposure", "label": "Public network access"},
                    ],
                ))

    # ── Container Registry with admin user ───────────────────────────
    for item in evidence_index.get("azure-containerregistry", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        admin = d.get("AdminUserEnabled", d.get("properties_adminUserEnabled", ""))
        if str(admin).lower() in ("true",):
            paths.append(ap_path(
                path_type="exposed_high_value",
                subtype="supply_chain",
                chain=f"Container Registry '{name}' has admin user enabled — "
                      f"credentials can be extracted to push malicious images.",
                risk_score=84,
                severity="high",
                resource_type="Container Registry",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Admin user enabled (push credentials exposed)",
                mitre_technique="T1525",
                mitre_tactic="Persistence",
                remediation="Disable admin user; use Entra RBAC for image push/pull.",
                ms_learn_url="https://learn.microsoft.com/azure/container-registry/container-registry-authentication",
                chain_nodes=[
                    {"type": "resource", "label": f"ACR '{name}'"},
                    {"type": "config", "label": "Admin user enabled"},
                    {"type": "impact", "label": "Push malicious images"},
                ],
            ))

    # ── AKS with public API server + no RBAC ─────────────────────────
    for item in evidence_index.get("azure-aks", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        rbac = d.get("EnableRBAC", d.get("properties_enableRBAC", ""))
        api_profile = d.get("ApiServerAccessProfile",
                     d.get("properties_apiServerAccessProfile", {}))
        is_private = False
        if isinstance(api_profile, dict):
            is_private = api_profile.get("enablePrivateCluster",
                        api_profile.get("privateCluster", False))
        if not is_private:
            if str(rbac).lower() in ("false", ""):
                paths.append(ap_path(
                    path_type="exposed_high_value",
                    subtype="aks_public_no_rbac",
                    chain=f"AKS cluster '{name}' has public API server AND Kubernetes RBAC disabled — "
                          f"any authenticated user has cluster-admin access.",
                    risk_score=92,
                    severity="critical",
                    resource_type="AKS Cluster",
                    resource_name=name,
                    resource_id=item.get("ResourceId", d.get("id", "")),
                    exposure="Public API server + RBAC disabled",
                    mitre_technique="T1610",
                    mitre_tactic="Execution",
                    remediation="Enable Kubernetes RBAC; configure authorized IP ranges or private cluster.",
                    ms_learn_url="https://learn.microsoft.com/azure/aks/operator-best-practices-cluster-security",
                    chain_nodes=[
                        {"type": "external", "label": "Internet"},
                        {"type": "resource", "label": f"AKS '{name}'"},
                        {"type": "config", "label": "Public API + No RBAC"},
                        {"type": "impact", "label": "Cluster-admin access"},
                    ],
                ))
            else:
                paths.append(ap_path(
                    path_type="exposed_high_value",
                    subtype="aks_public_api",
                    chain=f"AKS cluster '{name}' has public API server — "
                          f"API is exposed to the internet (RBAC is enabled).",
                    risk_score=72,
                    severity="medium",
                    resource_type="AKS Cluster",
                    resource_name=name,
                    resource_id=item.get("ResourceId", d.get("id", "")),
                    exposure="Public API server",
                    mitre_technique="T1610",
                    mitre_tactic="Execution",
                    remediation="Configure authorized IP ranges or enable private cluster.",
                    ms_learn_url="https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges",
                    chain_nodes=[
                        {"type": "external", "label": "Internet"},
                        {"type": "resource", "label": f"AKS '{name}'"},
                        {"type": "exposure", "label": "Public API server"},
                    ],
                ))

    # ── Redis Cache with non-SSL port or public access ───────────────
    for item in evidence_index.get("azure-redis-cache", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        non_ssl = d.get("EnableNonSslPort", d.get("properties_enableNonSslPort", ""))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        if str(non_ssl).lower() == "true":
            paths.append(ap_path(
                path_type="exposed_high_value",
                subtype="redis_non_ssl",
                chain=f"Redis Cache '{name}' has non-SSL port (6379) enabled — "
                      f"data in transit is unencrypted; session hijacking possible.",
                risk_score=78,
                severity="high",
                resource_type="Redis Cache",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Non-SSL port enabled",
                mitre_technique="T1040",
                mitre_tactic="Credential Access",
                remediation="Disable non-SSL port; require TLS 1.2 minimum.",
                ms_learn_url="https://learn.microsoft.com/azure/azure-cache-for-redis/cache-configure",
                chain_nodes=[
                    {"type": "resource", "label": f"Redis '{name}'"},
                    {"type": "config", "label": "Non-SSL port 6379"},
                    {"type": "exposure", "label": "Unencrypted traffic"},
                ],
            ))

    # ── Cognitive Services / AI with public + local auth ─────────────
    for item in evidence_index.get("azure-cognitive-account", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        local_auth = d.get("DisableLocalAuth", d.get("properties_disableLocalAuth", ""))
        if str(public).lower() in ("enabled", "true", "") and str(local_auth).lower() in ("false", ""):
            paths.append(ap_path(
                path_type="exposed_high_value",
                subtype="ai_service_exposed",
                chain=f"Cognitive/AI Service '{name}' has public network access AND local auth "
                      f"(API keys) enabled — attackers can extract keys and abuse the service.",
                risk_score=80,
                severity="high",
                resource_type="Cognitive/AI Service",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public access + API key auth",
                mitre_technique="T1552.001",
                mitre_tactic="Credential Access",
                remediation="Disable local auth (API keys); restrict to private endpoints; use Entra RBAC.",
                ms_learn_url="https://learn.microsoft.com/azure/ai-services/disable-local-auth",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"AI Service '{name}'"},
                    {"type": "exposure", "label": "Public + API keys"},
                ],
            ))

    # ── Data Factory with public + no managed VNet ───────────────────
    for item in evidence_index.get("azure-data-factory", []):
        d = item.get("Data", {})
        name = d.get("Name", d.get("name", "unknown"))
        public = d.get("PublicNetworkAccess", d.get("properties_publicNetworkAccess", ""))
        managed_vnet = d.get("ManagedVirtualNetwork", d.get("properties_managedVirtualNetwork", ""))
        has_mi = bool(d.get("Identity", d.get("identity", {})))
        if str(public).lower() in ("enabled", "true", "") and not managed_vnet:
            score = 82 if has_mi else 70
            paths.append(ap_path(
                path_type="exposed_high_value",
                subtype="data_factory_exposed",
                chain=f"Data Factory '{name}' has public access, no managed VNet"
                      f"{', and a managed identity' if has_mi else ''} — "
                      f"data movement pipelines can be exposed to the internet.",
                risk_score=score,
                severity="high" if score >= 80 else "medium",
                resource_type="Data Factory",
                resource_name=name,
                resource_id=item.get("ResourceId", d.get("id", "")),
                exposure="Public access + no managed VNet",
                mitre_technique="T1537",
                mitre_tactic="Exfiltration",
                remediation="Enable managed VNet for integration runtime; disable public network access.",
                ms_learn_url="https://learn.microsoft.com/azure/data-factory/managed-vnet-private-endpoint",
                chain_nodes=[
                    {"type": "external", "label": "Internet"},
                    {"type": "resource", "label": f"Data Factory '{name}'"},
                    {"type": "exposure", "label": "Public + no managed VNet"},
                ],
            ))

    return paths
