#!/usr/bin/env python3
"""
Generate 5 pages from DataSecurity.html template.

Reads DataSecurity.html, applies page-specific replacements for each target
page (RiskAnalysis, CopilotReadiness, AIAgentSecurity, RBACReport, CloudExplorer),
verifies div balance, and writes the output files.

Usage:  python generate_pages.py
"""
import re, pathlib, sys

WEBAPP = pathlib.Path(__file__).parent

# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS — generate HTML blocks from data structures
# ═══════════════════════════════════════════════════════════════

def ap_cats(groups):
    """Assess-panel category checkboxes (10-space indent)."""
    L = []
    L.append('          <label class="assess-fw-item select-all"><input type="checkbox" id="apFwSelectAll" onchange="toggleAllApFw(this)" checked/> Select All</label>')
    for icon_name, scope, items in groups:
        pill = 'Subscription' if scope == 'sub' else 'Tenant'
        L.append(f'          <div class="assess-group-hdr">{icon_name} <span class="scope-pill {scope}">{pill}</span></div>')
        for val, lab in items:
            L.append(f'          <label class="assess-fw-item"><input type="checkbox" class="ap-fw-cb" value="{val}" data-scope="{scope}" checked/> {lab}</label>')
    L.append('          <div class="assess-scope-note">Tenant-scoped categories scan your entire M365 tenant regardless of subscription selection.</div>')
    return '\n'.join(L)


def fw_cats(groups):
    """Framework-modal category checkboxes (6-space indent)."""
    L = []
    L.append('      <label class="select-all"><input type="checkbox" id="fwSelectAll" onchange="toggleAllFw(this)" checked/> Select All</label>')
    for icon_name, scope, items in groups:
        pill = 'Subscription' if scope == 'sub' else 'Tenant'
        L.append(f'      <div class="assess-group-hdr" style="margin-top:.5rem">{icon_name} <span class="scope-pill {scope}">{pill}</span></div>')
        for val, lab in items:
            L.append(f'      <label><input type="checkbox" class="fw-cb" value="{val}" checked/> {lab}</label>')
    return '\n'.join(L)


def perm_html(groups):
    """Permissions-panel prompts (6-space indent)."""
    L = []
    for icon, name, prompts in groups:
        L.append(f'      <div class="perm-panel-group">{icon} {name}</div>')
        for short_label, full_prompt in prompts:
            safe = full_prompt.replace("'", "\\'")
            L.append(
                f'      <button class="perm-panel-item" onclick="permPrompt(\'{safe}\')">'
                f'<span class="pi-icon">\u203a</span> {short_label}</button>'
            )
    return '\n'.join(L)


def ce_group_html(icon, name, prompts):
    """Single CE-panel prompt group (6-space indent)."""
    L = []
    L.append(f'      <div class="ce-panel-group">{icon} {name}</div>')
    for prompt_text, label in prompts:
        safe = prompt_text.replace("'", "\\'")
        L.append(
            f'      <button class="ce-panel-item" onclick="cePrompt(\'{safe}\')">'
            f'<span class="pi-icon">\u203a</span> {label}</button>'
        )
    return '\n'.join(L)

def ce_all_groups_html(groups):
    """All CE-panel prompt groups (6-space indent)."""
    parts = []
    for icon, name, prompts in groups:
        parts.append(ce_group_html(icon, name, prompts))
    return '\n'.join(parts)

# ═══════════════════════════════════════════════════════════════
# PAGE CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════

PAGES = {

# ─────────────── RISK ANALYSIS ───────────────
"RiskAnalysis": {
    "title": "Risk Assessment",
    "page_id": "RiskAnalysis",
    "logo": "\u26a0\ufe0f",      # ⚠️
    "avatar": "\u26a0",           # ⚠
    "login_desc": "Comprehensive risk assessment for Microsoft cloud environments. Evaluate identity, network, defender, configuration, and insider risk controls.",
    "login_roles": 'Required roles: <strong>Reader</strong> + <strong>Security Reader</strong> on target subscriptions.',
    "welcome_greeting": "Welcome to Risk Assessment",
    "welcome_sub": "Assess your risk posture across identity, network, defender, configuration, and insider risk",
    "qs_assess_desc": "Analyze risk signals and generate a prioritized risk posture report",
    "footer": "PostureIQ uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.",
    "assess_panel_desc": 'Select risk categories and subscription scope from the panel, then click <strong>Run</strong> to start your risk assessment.',
    "fw_modal_desc": "Choose which risk categories to include in your assessment.",
    "assess_name": "Risk Assessment",
    "assess_prompt_all": "Run a risk assessment on my tenant for all categories",
    "assess_prompt_partial": "Run a risk assessment on my tenant for these categories: ",
    "followup_domain": "risk",
    "categories": [
        ("\U0001f537 Azure Resources", "sub", [
            ("network", "Network Risk"),
            ("defender", "Defender Posture"),
            ("config", "Configuration Drift"),
        ]),
        ("\U0001f7e3 Microsoft 365 / Entra", "tenant", [
            ("identity", "Identity Risk"),
            ("insider_risk", "Insider Risk"),
        ]),
    ],
    "perm_groups": [
        ("\U0001f6e1", "Assessment Readiness", [
            ("all permissions for Risk Assessment?",
             "Check all permissions I need to run a full Risk Assessment covering identity, network, defender, configuration, and insider risk. Present results in a clear summary with a details section"),
            ("what permissions am I missing?",
             "What permissions am I missing to run a Risk Assessment? Check Azure RBAC Reader, SecurityEvents.Read.All, and Policy.Read.All. Present results in a clear summary with a details section"),
            ("verify readiness for all 5 categories",
             "Verify my readiness to run all 5 risk categories \u2014 check both Azure subscription access and Microsoft Graph tenant permissions. Present results in a clear summary with a details section"),
        ]),
    ],
    "ce_first": ("\u26a0\ufe0f", "Risk Assessment", [
        ("show Defender plans and secure score", "Defender plans & secure score"),
        ("list security recommendations", "security recommendations"),
        ("show policy compliance status", "policy compliance status"),
        ("list NSG rules allowing any source", "permissive NSG rules"),
        ("show public IPs", "show public IPs"),
        ("show conditional access policies", "conditional access policies"),
        ("show risky users", "show risky users"),
        ("show active defender alerts", "active Defender alerts"),
    ]),
    "ce_groups": [
        ("\u26a0\ufe0f", "Risk Assessment", [
            ("show Defender plans and secure score", "Defender plans & secure score"),
            ("list security recommendations", "security recommendations"),
            ("show policy compliance status", "policy compliance status"),
            ("list NSG rules allowing any source", "permissive NSG rules"),
            ("show public IPs", "show public IPs"),
            ("show conditional access policies", "conditional access policies"),
            ("show risky users", "show risky users"),
            ("show active defender alerts", "active Defender alerts"),
        ]),
        ("\U0001f5c4\ufe0f", "Databases", [
            ("list Cosmos DB accounts", "Cosmos DB accounts"),
            ("show SQL managed instances", "SQL managed instances"),
            ("show PostgreSQL servers", "PostgreSQL servers"),
            ("list Redis caches", "Redis caches"),
        ]),
        ("\U0001f512", "Encryption & Compliance", [
            ("show VMs without disk encryption", "VMs without disk encryption"),
            ("show Defender plans and secure score", "Defender plans & secure score"),
            ("show policy compliance status", "policy compliance status"),
            ("show policy compliance violations", "non-compliant resources"),
        ]),
        ("\U0001f6e1\ufe0f", "Security", [
            ("list security recommendations", "security recommendations"),
            ("list resource locks", "resource locks"),
            ("show Defender EASM assets", "external attack surface"),
            ("list JIT access policies", "JIT access policies"),
            ("show NSGs with any-any inbound rules", "permissive NSG rules"),
        ]),
        ("\U0001f465", "Identities", [
            ("list admin users", "admin users"),
            ("list service principals with Owner role", "overprivileged principals"),
            ("show risky users", "risky users"),
            ("list service principals", "service principals"),
            ("show conditional access policies", "conditional access policies"),
            ("list PIM eligible role assignments", "PIM eligible roles"),
        ]),
        ("\U0001f310", "Networking", [
            ("show all VNets and subnets", "VNets & subnets"),
            ("list NSG rules allowing any source", "open inbound rules"),
            ("show public IPs", "public IPs"),
            ("show Azure Firewalls", "Azure Firewalls"),
            ("list Front Door profiles", "Front Door profiles"),
        ]),
        ("\U0001f5a5\ufe0f", "Resources", [
            ("list all virtual machines", "virtual machines"),
            ("list all web apps", "web apps"),
            ("show all AKS clusters", "AKS clusters"),
            ("list all container apps", "container apps"),
            ("show all function apps", "function apps"),
        ]),
        ("\U0001f4ca", "Big Data & Analytics", [
            ("list Synapse workspaces", "Synapse workspaces"),
            ("show Data Factory instances", "Data Factory instances"),
            ("list Databricks workspaces", "Databricks workspaces"),
            ("show Data Explorer clusters", "Data Explorer clusters"),
        ]),
        ("\U0001f3d7\ufe0f", "Infrastructure", [
            ("show all subscriptions", "show all subscriptions"),
            ("list resource groups", "resource groups"),
            ("show management groups", "management group hierarchy"),
            ("list all tags in use", "tags in use"),
        ]),
        ("\U0001f4dc", "Governance", [
            ("list all policy assignments", "policy assignments"),
            ("list blueprints and initiatives", "blueprints & initiatives"),
            ("list custom RBAC role definitions", "custom RBAC roles"),
            ("show deny assignments", "deny assignments"),
        ]),
        ("\U0001f4e1", "Monitoring", [
            ("list resources without diagnostic settings", "resources without diagnostics"),
            ("list Log Analytics workspaces", "Log Analytics workspaces"),
            ("list Sentinel workspaces", "Sentinel workspaces"),
            ("list alert rules and action groups", "alert rules & action groups"),
        ]),
        ("\U0001f50d", "Filtered Queries", [
            ("count resources by type across all subscriptions", "resource count by type"),
            ("show resources tagged with environment=production", "resources tagged production"),
            ("list resources created in the last 7 days", "resources created last 7 days"),
        ]),
    ],
},

# ─────────────── COPILOT READINESS ───────────────
"CopilotReadiness": {
    "title": "Copilot Readiness Assessment",
    "page_id": "CopilotReadiness",
    "logo": "\U0001f916",         # 🤖
    "avatar": "\U0001f916",
    "login_desc": "Microsoft 365 Copilot readiness assessment. Evaluate oversharing risk, label coverage, DLP readiness, access governance, and content lifecycle.",
    "login_roles": 'Required roles: <strong>Global Reader</strong> + <strong>Security Reader</strong> on your Microsoft 365 tenant.',
    "welcome_greeting": "Welcome to Copilot Readiness Assessment",
    "welcome_sub": "Assess your M365 Copilot readiness across oversharing, labels, DLP, and access governance",
    "qs_assess_desc": "Score your Copilot readiness and surface data exposure risks",
    "footer": "PostureIQ uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.",
    "assess_panel_desc": 'Select copilot readiness categories from the panel, then click <strong>Run</strong> to start your readiness assessment.',
    "fw_modal_desc": "Choose which copilot readiness categories to include in your assessment.",
    "assess_name": "Copilot Readiness Assessment",
    "assess_prompt_all": "Run a copilot readiness assessment on my tenant for all categories",
    "assess_prompt_partial": "Run a copilot readiness assessment on my tenant for these categories: ",
    "followup_domain": "copilot readiness",
    "categories": [
        ("\U0001f7e3 Microsoft 365 / Copilot", "tenant", [
            ("oversharing_risk", "Oversharing Risk"),
            ("label_coverage", "Sensitivity Label Coverage"),
            ("dlp_readiness", "DLP Readiness"),
            ("restricted_search", "Restricted SharePoint Search"),
            ("access_governance", "Access Governance"),
            ("content_lifecycle", "Content Lifecycle"),
            ("audit_monitoring", "Audit & Monitoring"),
            ("copilot_security", "Copilot Security"),
            ("zero_trust", "Zero Trust"),
            ("shadow_ai", "Shadow AI"),
        ]),
    ],
    "perm_groups": [
        ("\U0001f6e1", "Assessment Readiness", [
            ("all permissions for Copilot Readiness Assessment?",
             "Check all permissions I need to run a full Copilot Readiness Assessment covering oversharing, labels, DLP, access governance, and content lifecycle. Present results in a clear summary with a details section"),
            ("what permissions am I missing?",
             "What permissions am I missing to run a Copilot Readiness Assessment? Check Global Reader, InformationProtection.Read.All, SecurityAlert.Read.All. Present results in a clear summary with a details section"),
            ("verify readiness for all 10 categories",
             "Verify my readiness to run all 10 copilot readiness categories \u2014 check Microsoft Graph tenant permissions. Present results in a clear summary with a details section"),
        ]),
    ],
    "ce_first": ("\U0001f916", "Copilot & M365", [
        ("show conditional access policies", "conditional access policies"),
        ("list admin users", "list admin users"),
        ("show risky users", "show risky users"),
        ("list service principals", "list service principals"),
        ("show consent grants", "consent grants"),
        ("list all policy assignments", "policy assignments"),
        ("show policy compliance status", "policy compliance status"),
        ("list security recommendations", "security recommendations"),
    ]),
    "ce_groups": [
        ("\U0001f916", "Copilot & M365", [
            ("show conditional access policies", "conditional access policies"),
            ("list admin users", "list admin users"),
            ("show risky users", "show risky users"),
            ("list service principals", "list service principals"),
            ("show consent grants", "consent grants"),
            ("list all policy assignments", "policy assignments"),
            ("show policy compliance status", "policy compliance status"),
            ("list security recommendations", "security recommendations"),
        ]),
        ("\U0001f5c4\ufe0f", "Databases", [
            ("list Cosmos DB accounts", "Cosmos DB accounts"),
            ("show SQL managed instances", "SQL managed instances"),
            ("show PostgreSQL servers", "PostgreSQL servers"),
            ("list Redis caches", "Redis caches"),
        ]),
        ("\U0001f512", "Encryption & Compliance", [
            ("show VMs without disk encryption", "VMs without disk encryption"),
            ("show Defender plans and secure score", "Defender plans & secure score"),
            ("show policy compliance status", "policy compliance status"),
            ("show policy compliance violations", "non-compliant resources"),
        ]),
        ("\U0001f6e1\ufe0f", "Security", [
            ("list security recommendations", "security recommendations"),
            ("list resource locks", "resource locks"),
            ("show Defender EASM assets", "external attack surface"),
            ("list JIT access policies", "JIT access policies"),
            ("show NSGs with any-any inbound rules", "permissive NSG rules"),
        ]),
        ("\U0001f465", "Identities", [
            ("list admin users", "admin users"),
            ("list service principals with Owner role", "overprivileged principals"),
            ("show risky users", "risky users"),
            ("list service principals", "service principals"),
            ("show conditional access policies", "conditional access policies"),
            ("list PIM eligible role assignments", "PIM eligible roles"),
        ]),
        ("\U0001f310", "Networking", [
            ("show all VNets and subnets", "VNets & subnets"),
            ("list NSG rules allowing any source", "open inbound rules"),
            ("show public IPs", "public IPs"),
            ("show Azure Firewalls", "Azure Firewalls"),
            ("list Front Door profiles", "Front Door profiles"),
        ]),
        ("\U0001f5a5\ufe0f", "Resources", [
            ("list all virtual machines", "virtual machines"),
            ("list all web apps", "web apps"),
            ("show all AKS clusters", "AKS clusters"),
            ("list all container apps", "container apps"),
            ("show all function apps", "function apps"),
        ]),
        ("\U0001f4ca", "Big Data & Analytics", [
            ("list Synapse workspaces", "Synapse workspaces"),
            ("show Data Factory instances", "Data Factory instances"),
            ("list Databricks workspaces", "Databricks workspaces"),
            ("show Data Explorer clusters", "Data Explorer clusters"),
        ]),
        ("\U0001f3d7\ufe0f", "Infrastructure", [
            ("show all subscriptions", "show all subscriptions"),
            ("list resource groups", "resource groups"),
            ("show management groups", "management group hierarchy"),
            ("list all tags in use", "tags in use"),
        ]),
        ("\U0001f4dc", "Governance", [
            ("list all policy assignments", "policy assignments"),
            ("list blueprints and initiatives", "blueprints & initiatives"),
            ("list custom RBAC role definitions", "custom RBAC roles"),
            ("show deny assignments", "deny assignments"),
        ]),
        ("\U0001f4e1", "Monitoring", [
            ("list resources without diagnostic settings", "resources without diagnostics"),
            ("list Log Analytics workspaces", "Log Analytics workspaces"),
            ("list Sentinel workspaces", "Sentinel workspaces"),
            ("list alert rules and action groups", "alert rules & action groups"),
        ]),
        ("\U0001f50d", "Filtered Queries", [
            ("count resources by type across all subscriptions", "resource count by type"),
            ("show resources tagged with environment=production", "resources tagged production"),
            ("list resources created in the last 7 days", "resources created last 7 days"),
        ]),
    ],
},

# ─────────────── AI AGENT SECURITY ───────────────
"AIAgentSecurity": {
    "title": "AI Agent Security Assessment",
    "page_id": "AIAgentSecurity",
    "logo": "\U0001f9e0",         # 🧠
    "avatar": "\U0001f9e0",
    "login_desc": "AI agent security assessment for Microsoft cloud. Evaluate Copilot Studio, Azure AI Foundry, custom AI agents, and Entra AI identity security.",
    "login_roles": 'Required roles: <strong>Reader</strong> + <strong>Security Reader</strong> on target subscriptions.',
    "welcome_greeting": "Welcome to AI Agent Security Assessment",
    "welcome_sub": "Assess your AI agent security across Copilot Studio, AI Foundry, custom agents, and Entra AI",
    "qs_assess_desc": "Scan AI agent configurations and generate a security posture report",
    "footer": "PostureIQ uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.",
    "assess_panel_desc": 'Select AI agent security categories and subscription scope from the panel, then click <strong>Run</strong> to start your AI agent security assessment.',
    "fw_modal_desc": "Choose which AI agent security categories to include in your assessment.",
    "assess_name": "AI Agent Security Assessment",
    "assess_prompt_all": "Run an AI agent security assessment on my tenant for all categories",
    "assess_prompt_partial": "Run an AI agent security assessment on my tenant for these categories: ",
    "followup_domain": "AI agent security",
    "categories": [
        ("\U0001f535 Copilot Studio", "tenant", [
            ("cs_authentication", "Authentication"),
            ("cs_data_connectors", "Data Connectors"),
            ("cs_logging", "Logging"),
            ("cs_channels", "Channels"),
            ("cs_knowledge_sources", "Knowledge Sources"),
            ("cs_generative_ai", "Generative AI"),
            ("cs_governance", "Governance"),
            ("cs_connector_security", "Connector Security"),
            ("cs_dlp_depth", "DLP Depth"),
            ("cs_environment_governance", "Environment Governance"),
            ("cs_agent_security_advanced", "Advanced Agent Security"),
            ("cs_audit_compliance", "Audit & Compliance"),
            ("cs_dataverse_security", "Dataverse Security"),
            ("cs_readiness_crosscheck", "Readiness Cross-check"),
        ]),
        ("\U0001f7e3 Azure AI Foundry", "sub", [
            ("foundry_network", "Network Isolation"),
            ("foundry_identity", "Identity & Access"),
            ("foundry_content_safety", "Content Safety"),
            ("foundry_deployments", "Deployments"),
            ("foundry_governance", "Governance"),
            ("foundry_compute", "Compute Security"),
            ("foundry_datastores", "Datastore Security"),
            ("foundry_endpoints", "Endpoint Security"),
            ("foundry_registry", "Model Registry"),
            ("foundry_connections", "Connection Security"),
            ("foundry_serverless", "Serverless Security"),
            ("foundry_ws_diagnostics", "Workspace Diagnostics"),
            ("foundry_prompt_shields", "Prompt Shields"),
            ("foundry_model_catalog", "Model Catalog"),
            ("foundry_data_exfiltration", "Data Exfiltration"),
            ("foundry_agent_identity", "Agent Identity"),
            ("foundry_agent_application", "Agent Application"),
            ("foundry_mcp_tools", "MCP Tools"),
            ("foundry_tool_security", "Tool Security"),
            ("foundry_guardrails", "Guardrails"),
            ("foundry_hosted_agents", "Hosted Agents"),
            ("foundry_data_resources", "Data Resources"),
            ("foundry_observability", "Observability"),
            ("foundry_lifecycle", "Lifecycle"),
        ]),
        ("\U0001f7e4 Custom AI Agents", "sub", [
            ("custom_api_security", "API Security"),
            ("custom_data_residency", "Data Residency"),
            ("custom_content_leakage", "Content Leakage"),
        ]),
        ("\U0001f537 Entra AI Identity", "tenant", [
            ("entra_ai_service_principals", "AI Service Principals"),
            ("entra_ai_conditional_access", "Conditional Access"),
            ("entra_ai_consent", "AI Consent"),
            ("entra_ai_workload_identity", "Workload Identity"),
            ("entra_ai_cross_tenant", "Cross-Tenant Access"),
            ("entra_ai_privileged_access", "Privileged Access"),
        ]),
        ("\U0001f3d7\ufe0f AI Infrastructure", "sub", [
            ("ai_diagnostics", "AI Diagnostics"),
            ("ai_model_governance", "Model Governance"),
            ("ai_threat_protection", "Threat Protection"),
            ("ai_data_governance", "Data Governance"),
            ("ai_defender_coverage", "Defender Coverage"),
            ("ai_policy_compliance", "Policy Compliance"),
        ]),
        ("\U0001f504 Agent Orchestration", "sub", [
            ("agent_communication", "Agent Communication"),
            ("agent_governance", "Agent Governance"),
        ]),
    ],
    "perm_groups": [
        ("\U0001f6e1", "Assessment Readiness", [
            ("all permissions for AI Agent Security Assessment?",
             "Check all permissions I need to run a full AI Agent Security Assessment covering Copilot Studio, AI Foundry, custom agents, and Entra AI identity. Present results in a clear summary with a details section"),
            ("what permissions am I missing?",
             "What permissions am I missing to run an AI Agent Security Assessment? Check Azure Reader, SecurityEvents.Read.All, and cognitive services access. Present results in a clear summary with a details section"),
            ("verify readiness for all categories",
             "Verify my readiness to run all AI agent security categories \u2014 check both Azure subscription access and Microsoft Graph tenant permissions. Present results in a clear summary with a details section"),
        ]),
    ],
    "ce_first": ("\U0001f9e0", "AI & Agent Security", [
        ("list Azure OpenAI resources", "Azure OpenAI resources"),
        ("show ML workspaces", "ML workspaces"),
        ("show Azure AI Search services", "AI Search services"),
        ("list cognitive services", "cognitive services"),
        ("show all AKS clusters", "AKS clusters"),
        ("list all container apps", "container apps"),
        ("show private endpoints", "private endpoints"),
        ("show API Management services", "API Management"),
    ]),
    "ce_groups": [
        ("\U0001f9e0", "AI & Agent Security", [
            ("list Azure OpenAI resources", "Azure OpenAI resources"),
            ("show ML workspaces", "ML workspaces"),
            ("show Azure AI Search services", "AI Search services"),
            ("list cognitive services", "cognitive services"),
            ("show all AKS clusters", "AKS clusters"),
            ("list all container apps", "container apps"),
            ("show private endpoints", "private endpoints"),
            ("show API Management services", "API Management"),
        ]),
        ("\U0001f5c4\ufe0f", "Databases", [
            ("list Cosmos DB accounts", "Cosmos DB accounts"),
            ("show SQL managed instances", "SQL managed instances"),
            ("show PostgreSQL servers", "PostgreSQL servers"),
            ("list Redis caches", "Redis caches"),
        ]),
        ("\U0001f512", "Encryption & Compliance", [
            ("show VMs without disk encryption", "VMs without disk encryption"),
            ("show Defender plans and secure score", "Defender plans & secure score"),
            ("show policy compliance status", "policy compliance status"),
            ("show policy compliance violations", "non-compliant resources"),
        ]),
        ("\U0001f6e1\ufe0f", "Security", [
            ("list security recommendations", "security recommendations"),
            ("list resource locks", "resource locks"),
            ("show Defender EASM assets", "external attack surface"),
            ("list JIT access policies", "JIT access policies"),
            ("show NSGs with any-any inbound rules", "permissive NSG rules"),
        ]),
        ("\U0001f465", "Identities", [
            ("list admin users", "admin users"),
            ("list service principals with Owner role", "service principal owners"),
            ("show risky users", "risky users"),
            ("list service principals", "service principals"),
            ("show conditional access policies", "conditional access policies"),
            ("list PIM eligible role assignments", "PIM eligible roles"),
        ]),
        ("\U0001f310", "Networking", [
            ("show all VNets and subnets", "VNets and subnets"),
            ("list NSG rules allowing any source", "open inbound rules"),
            ("show public IPs", "public IPs"),
            ("show Azure Firewalls", "Azure Firewalls"),
            ("list Front Door profiles", "Front Door profiles"),
        ]),
        ("\U0001f5a5\ufe0f", "Resources", [
            ("list all virtual machines", "virtual machines"),
            ("list all web apps", "web apps"),
            ("show all AKS clusters", "AKS clusters"),
            ("list all container apps", "container apps"),
            ("show all function apps", "function apps"),
        ]),
        ("\U0001f4ca", "Big Data & Analytics", [
            ("list Synapse workspaces", "Synapse workspaces"),
            ("show Data Factory instances", "Data Factory instances"),
            ("list Databricks workspaces", "Databricks workspaces"),
            ("show Data Explorer clusters", "Data Explorer clusters"),
        ]),
        ("\U0001f3d7\ufe0f", "Infrastructure", [
            ("show all subscriptions", "show all subscriptions"),
            ("list resource groups", "resource groups"),
            ("show management groups", "management groups"),
            ("list all tags in use", "tags in use"),
        ]),
        ("\U0001f4dc", "Governance", [
            ("list all policy assignments", "policy assignments"),
            ("list blueprints and initiatives", "blueprints & initiatives"),
            ("list custom RBAC role definitions", "custom RBAC roles"),
            ("show deny assignments", "deny assignments"),
        ]),
        ("\U0001f4e1", "Monitoring", [
            ("list resources without diagnostic settings", "resources without diagnostics"),
            ("list Log Analytics workspaces", "Log Analytics workspaces"),
            ("list Sentinel workspaces", "Sentinel workspaces"),
            ("list alert rules and action groups", "alert rules & action groups"),
        ]),
        ("\U0001f50d", "Filtered Queries", [
            ("count resources by type across all subscriptions", "resource count by type"),
            ("show resources tagged with environment=production", "resources tagged production"),
            ("list resources created in the last 7 days", "resources created last 7 days"),
        ]),
    ],
},

# ─────────────── RBAC REPORT ───────────────
"RBACReport": {
    "title": "RBAC Assessment",
    "page_id": "RBACReport",
    "logo": "\U0001f511",         # 🔑
    "avatar": "\U0001f511",
    "login_desc": "RBAC role assignment hierarchy assessment for Azure. Enumerate management groups, subscriptions, resource groups, and role assignments.",
    "login_roles": 'Required roles: <strong>Reader</strong> on target subscriptions.',
    "welcome_greeting": "Welcome to RBAC Assessment",
    "welcome_sub": "Assess your RBAC assignments across management groups, subscriptions, and resource groups",
    "qs_assess_desc": "Map role assignments, flag over-privileged accounts, and generate an RBAC report",
    "footer": "PostureIQ uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.",
    "assess_panel_desc": 'Select assessment scope from the panel, then click <strong>Run</strong> to start your RBAC assessment.',
    "fw_modal_desc": "Select your RBAC assessment scope.",
    "assess_name": "RBAC Assessment",
    "assess_prompt_all": "Run a RBAC assessment on my tenant",
    "assess_prompt_partial": "Run a RBAC assessment on my tenant covering: ",
    "followup_domain": "RBAC",
    "categories": [
        ("\U0001f511 RBAC Report", "sub", [
            ("rbac_tree", "Full RBAC Hierarchy"),
        ]),
    ],
    "perm_groups": [
        ("\U0001f6e1", "Assessment Readiness", [
            ("all permissions for RBAC Assessment?",
             "Check all permissions I need to run a full RBAC assessment covering management groups, subscriptions, resource groups, and resources. Present results in a clear summary with a details section"),
            ("what permissions am I missing?",
             "What permissions am I missing to run a RBAC assessment? Check Reader role and Management Group Reader access. Present results in a clear summary with a details section"),
            ("verify readiness for RBAC assessment",
             "Verify my readiness to run a complete RBAC hierarchy assessment across all subscriptions. Present results in a clear summary with a details section"),
        ]),
    ],
    "ce_first": ("\U0001f511", "RBAC & Access", [
        ("list admin users", "list admin users"),
        ("show conditional access policies", "conditional access policies"),
        ("list service principals with Owner role", "service principals with Owner"),
        ("list PIM eligible role assignments", "PIM eligible roles"),
        ("show all subscriptions", "show all subscriptions"),
        ("list custom RBAC role definitions", "custom RBAC roles"),
        ("show deny assignments", "deny assignments"),
        ("show management groups", "management groups"),
    ]),
    "ce_groups": [
        ("\U0001f511", "RBAC & Access", [
            ("list admin users", "list admin users"),
            ("show conditional access policies", "conditional access policies"),
            ("list service principals with Owner role", "service principals with Owner"),
            ("list PIM eligible role assignments", "PIM eligible roles"),
            ("show all subscriptions", "show all subscriptions"),
            ("list custom RBAC role definitions", "custom RBAC roles"),
            ("show deny assignments", "deny assignments"),
            ("show management groups", "management groups"),
        ]),
        ("\U0001f5c4\ufe0f", "Databases", [
            ("list Cosmos DB accounts", "Cosmos DB accounts"),
            ("show SQL managed instances", "SQL managed instances"),
            ("show PostgreSQL servers", "PostgreSQL servers"),
            ("list Redis caches", "Redis caches"),
        ]),
        ("\U0001f512", "Encryption & Compliance", [
            ("show VMs without disk encryption", "VMs without disk encryption"),
            ("show Defender plans and secure score", "Defender plans & secure score"),
            ("show policy compliance status", "policy compliance status"),
            ("show policy compliance violations", "non-compliant resources"),
        ]),
        ("\U0001f6e1\ufe0f", "Security", [
            ("list security recommendations", "security recommendations"),
            ("list resource locks", "resource locks"),
            ("show Defender EASM assets", "external attack surface"),
            ("list JIT access policies", "JIT access policies"),
            ("show NSGs with any-any inbound rules", "permissive NSG rules"),
        ]),
        ("\U0001f465", "Identities", [
            ("list admin users", "admin users"),
            ("list service principals with Owner role", "overprivileged principals"),
            ("show risky users", "risky users"),
            ("list service principals", "service principals"),
            ("show conditional access policies", "conditional access policies"),
            ("list PIM eligible role assignments", "PIM eligible roles"),
        ]),
        ("\U0001f310", "Networking", [
            ("show all VNets and subnets", "VNets & subnets"),
            ("list NSG rules allowing any source", "open inbound rules"),
            ("show public IPs", "public IPs"),
            ("show Azure Firewalls", "Azure Firewalls"),
            ("list Front Door profiles", "Front Door profiles"),
        ]),
        ("\U0001f5a5\ufe0f", "Resources", [
            ("list all virtual machines", "virtual machines"),
            ("list all web apps", "web apps"),
            ("show all AKS clusters", "AKS clusters"),
            ("list all container apps", "container apps"),
            ("show all function apps", "function apps"),
        ]),
        ("\U0001f4ca", "Big Data & Analytics", [
            ("list Synapse workspaces", "Synapse workspaces"),
            ("show Data Factory instances", "Data Factory instances"),
            ("list Databricks workspaces", "Databricks workspaces"),
            ("show Data Explorer clusters", "Data Explorer clusters"),
        ]),
        ("\U0001f3d7\ufe0f", "Infrastructure", [
            ("show all subscriptions", "show all subscriptions"),
            ("list resource groups", "resource groups"),
            ("show management groups", "management group hierarchy"),
            ("list all tags in use", "tags in use"),
        ]),
        ("\U0001f4dc", "Governance", [
            ("list all policy assignments", "policy assignments"),
            ("list blueprints and initiatives", "blueprints & initiatives"),
            ("list custom RBAC role definitions", "custom RBAC roles"),
            ("show deny assignments", "deny assignments"),
        ]),
        ("\U0001f4e1", "Monitoring", [
            ("list resources without diagnostic settings", "resources without diagnostics"),
            ("list Log Analytics workspaces", "Log Analytics workspaces"),
            ("list Sentinel workspaces", "Sentinel workspaces"),
            ("list alert rules and action groups", "alert rules & action groups"),
        ]),
        ("\U0001f50d", "Filtered Queries", [
            ("count resources by type across all subscriptions", "resource count by type"),
            ("show resources tagged with environment=production", "resources tagged production"),
            ("list resources created in the last 7 days", "resources created last 7 days"),
        ]),
    ],
},

# ─────────────── CLOUD EXPLORER (standalone) ───────────────
"CloudExplorer": {
    "title": "Cloud Explorer",
    "page_id": "CloudExplorer",
    "logo": "\u2601\ufe0f",      # ☁️
    "avatar": "\u2601",           # ☁
    "login_desc": "Explore your Microsoft cloud environment in real time. Query Azure resources, identities, security settings, and infrastructure.",
    "login_roles": 'Required roles: <strong>Reader</strong> + <strong>Security Reader</strong> on target subscriptions.',
    "welcome_greeting": "Welcome to Cloud Explorer",
    "welcome_sub": "Explore your Microsoft cloud environment in real time",
    "qs_assess_desc": "Query Azure resources, identities &amp; security settings",  # unused but needed for replacement
    "footer": "PostureIQ uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.",
    "assess_panel_desc": '',  # unused — assess panel is removed for this page
    "fw_modal_desc": '',      # unused — fw modal is removed for this page
    "assess_name": "Cloud Explorer",
    "assess_prompt_all": "",
    "assess_prompt_partial": "",
    "followup_domain": "cloud explorer",
    "categories": [],  # no assessment categories
    "perm_groups": [
        ("\U0001f6e1", "Assessment Readiness", [
            ("check all my permissions",
             "Check all my permissions including Azure RBAC roles, Entra directory roles, and Microsoft Graph API access. Present results in a clear summary with a details section"),
            ("what can I access?",
             "What Azure subscriptions and resources can I access with my current roles? Present results in a clear summary with a details section"),
            ("verify my Reader access",
             "Verify I have Reader and Security Reader roles on my target subscriptions for full Cloud Explorer results. Present results in a clear summary with a details section"),
        ]),
    ],
    "ce_first": ("\u2601\ufe0f", "Quick Start", [
        ("show all subscriptions", "show all subscriptions"),
        ("list all virtual machines", "list all virtual machines"),
        ("list admin users", "list admin users"),
        ("show all storage accounts", "show all storage accounts"),
        ("show Defender plans and secure score", "Defender plans & secure score"),
        ("list security recommendations", "security recommendations"),
        ("show all AKS clusters", "AKS clusters"),
        ("list resource groups", "list resource groups"),
    ]),
    "is_cloud_explorer": True,
},

}  # end PAGES


# ═══════════════════════════════════════════════════════════════
# GENERATOR
# ═══════════════════════════════════════════════════════════════

def generate(template, cfg):
    """Apply all page-specific replacements to the DataSecurity template."""
    h = template

    # ── SIMPLE STRING REPLACEMENTS (ordered longest → shortest for safety) ──

    # S1: Login description
    h = h.replace(
        'Data security posture assessment for Microsoft cloud. '
        'Audit storage, databases, Key Vault, encryption, classification, and data lifecycle controls.',
        cfg["login_desc"])

    # S2: showAssessPanel center description
    h = h.replace(
        'Select data security categories and subscription scope from the panel, '
        'then click <strong>Run</strong> to start your data security assessment.',
        cfg["assess_panel_desc"])

    # S3: Framework modal description
    h = h.replace(
        'Choose which data security categories to include in your assessment.',
        cfg["fw_modal_desc"])

    # S4: Assessment label — full (before partial S5!)
    h = h.replace('Data Security Assessment (All Categories)',
                   cfg["assess_name"] + ' (All Categories)')

    # S5: Assessment label — partial prefix
    h = h.replace('Data Security Assessment (',
                   cfg["assess_name"] + ' (')

    # S6: Assessment prompt — all categories
    h = h.replace('Run a data security assessment on my tenant for all categories',
                   cfg["assess_prompt_all"])

    # S7: Assessment prompt — partial categories
    h = h.replace('Run a data security assessment on my tenant for these categories: ',
                   cfg["assess_prompt_partial"])

    # S8: HTML title (must use full tag to avoid replacing h1/header matches)
    h = h.replace('<title>PostureIQ - Data Security Assessment</title>',
                   '<title>PostureIQ - ' + cfg["title"] + '</title>')

    # S9: Login h1
    h = h.replace('<h1>PostureIQ - Data Security Assessment</h1>',
                   '<h1>PostureIQ - ' + cfg["title"] + '</h1>')

    # S10: Login logo
    h = h.replace('<div class="logo">\U0001f6e1\ufe0f</div>',
                   '<div class="logo">' + cfg["logo"] + '</div>')

    # S11: Header logo icon
    h = h.replace('<span class="hdr-logo-icon">\U0001f6e1\ufe0f</span>',
                   '<span class="hdr-logo-icon">' + cfg["logo"] + '</span>')

    # S12: Header title
    h = h.replace('<span class="hdr-title">PostureIQ - Data Security Assessment</span>',
                   '<span class="hdr-title">PostureIQ - ' + cfg["title"] + '</span>')

    # S13: Header aria-label
    h = h.replace('aria-label="PostureIQ - Data Security Assessment Home"',
                   'aria-label="PostureIQ - ' + cfg["title"] + ' Home"')

    # S14: body.page in sendChat
    h = h.replace('body.page = "DataSecurity";',
                   'body.page = "' + cfg["page_id"] + '";')

    # S15: Typing indicator avatar (plain emoji without variation selector)
    h = h.replace('<div class="msg-avatar">\U0001f6e1</div>',
                   '<div class="msg-avatar">' + cfg["avatar"] + '</div>')

    # S16: Chat footer
    h = h.replace(
        'PostureIQ uses your signed-in credentials to query Microsoft cloud services. '
        'Results reflect your permission level.',
        cfg["footer"])

    # S17: Welcome greeting (appears 2×: HTML + resetChat JS)
    h = h.replace('Welcome to Data Security Assessment', cfg["welcome_greeting"])

    # S18: Welcome subtitle (appears 2×)
    h = h.replace('Assess your data security across storage, encryption, classification, and lifecycle controls',
                   cfg["welcome_sub"])

    # S19: QS card assess description (appears 2×)
    h = h.replace('Evaluate data protection controls and generate a scored security report',
                   cfg["qs_assess_desc"])

    # S20: Login required roles
    h = h.replace(
        'Required roles: <strong>Reader</strong> + <strong>Security Reader</strong> on target subscriptions.',
        cfg["login_roles"])

    # S21-S23: FOLLOWUP_MAP domain-specific strings
    domain = cfg["followup_domain"]
    h = h.replace('Which data security categories scored lowest and why',
                   'Which ' + domain + ' categories scored lowest and why')
    h = h.replace('lowest scoring data security category',
                   'lowest scoring ' + domain + ' category')
    h = h.replace('across all assessed data security categories',
                   'across all assessed ' + domain + ' categories')

    # ── BLOCK REPLACEMENTS ──

    # B1: CE panel — replace all prompt groups (or just first if only ce_first)
    ce_list_tag = '<div class="ce-panel-list">'
    try:
        if cfg.get("ce_groups"):
            i_start = h.index(ce_list_tag) + len(ce_list_tag)
            close_pat = '\n    </div>\n  </div>\n  <button class="ce-tab"'
            i_end = h.index(close_pat, i_start)
            new_content = '\n' + ce_all_groups_html(cfg["ce_groups"])
            h = h[:i_start] + new_content + h[i_end:]
        else:
            ce_group_tag = '<div class="ce-panel-group">'
            i1 = h.index(ce_list_tag) + len(ce_list_tag)
            i2 = h.index(ce_group_tag, i1)
            i3 = h.index(ce_group_tag, i2 + 1)
            icon, name, prompts = cfg["ce_first"]
            new_ce = ce_group_html(icon, name, prompts)
            h = h[:i2] + new_ce + '\n' + h[i3:]
    except ValueError as e:
        print(f"  ! CE group replacement failed: {e}")

    # B2: Assess panel categories
    h = re.sub(
        r'(<div class="assess-fw-grid">\n).*?'
        r'(\n {8}</div>\n {6}</div>\n {6}<div id="apSubSection">)',
        lambda m: m.group(1) + ap_cats(cfg["categories"]) + m.group(2),
        h, count=1, flags=re.DOTALL)

    # B3: Framework modal categories
    h = re.sub(
        r'(<div class="fw-grid">\n).*?'
        r'(\n {4}</div>\n {4}<div class="modal-actions">)',
        lambda m: m.group(1) + fw_cats(cfg["categories"]) + m.group(2),
        h, count=1, flags=re.DOTALL)

    # B4: Permissions panel prompts
    h = re.sub(
        r'(<div class="perm-panel-list">\n).*?'
        r'(\n {4}</div>\n {2}</div>\n {2}<button class="perm-tab")',
        lambda m: m.group(1) + perm_html(cfg["perm_groups"]) + m.group(2),
        h, count=1, flags=re.DOTALL)

    # ── CLOUD EXPLORER POST-PROCESSING ──
    if cfg.get("is_cloud_explorer"):
        h = strip_for_cloud_explorer(h)

    return h


def strip_for_cloud_explorer(h):
    """Remove assess panel, framework modal, and Run Assessment nav from CloudExplorer page."""

    # R1: Remove "Run Assessment" header nav button
    h = re.sub(
        r' {6}<button class="hdr-nav-link" id="navAssessment"[^>]*>.*?</button>\n',
        '', h, count=1, flags=re.DOTALL)

    # R2: Remove assess panel HTML + tab (from <!-- Assessment Floating Panel to assess-tab button inclusive)
    h = re.sub(
        r'\n {2}<!-- Assessment Floating Panel.*?'
        r'<button class="assess-tab"[^>]*>.*?</button>',
        '', h, count=1, flags=re.DOTALL)

    # R3: Remove framework modal HTML
    h = re.sub(
        r'\n<!-- Category Picker Modal -->\n'
        r'<div class="modal-overlay" id="fwModalOverlay".*?</div>\n</div>',
        '', h, count=1, flags=re.DOTALL)

    # R4: Replace 3-card QS grid with 2-card grid (remove Run Assessment card) — in the HTML landing
    # The Run Assessment card calls showAssessPanel()
    h = re.sub(
        r'( {12}<div class="qs-card" onclick="showAssessPanel\(\)">'
        r'.*?</div>\n {12}</div>\n)',
        '', h, count=1, flags=re.DOTALL)

    # R5: Replace 3-card QS grid with 2-card grid in resetChat() JS string
    # Remove the Run Assessment card from the JS string concatenation in resetChat
    h = re.sub(
        r"""(\+ '<div class="qs-cards">')\n"""
        r""" *\+ '<div class="qs-card" onclick="showAssessPanel\(\)">.*?</div></div>'\n""",
        r'\1\n', h, count=1)

    # R6: In newChatForTool, the Assessment branch won't match since there's no assess nav,
    # but leave it because it's a harmless no-op (never triggered).

    # R7: Update chat input placeholder for cloud explorer default
    h = h.replace(
        'placeholder="Ask the agent anything\u2026"',
        'placeholder="Ask anything \u2014 e.g., \u201clist all VMs\u201d, \u201cshow admin users\u201d, \u201cstorage accounts\u201d\u2026"')

    return h


# ═══════════════════════════════════════════════════════════════
# VERIFICATION
# ═══════════════════════════════════════════════════════════════

def verify(html, name):
    """Check structural integrity of generated HTML."""
    ok = True

    # Div balance
    opens = html.count('<div')
    closes = html.count('</div>')
    if opens != closes:
        print(f"  \u2717 {name}: div imbalance ({opens} opens vs {closes} closes)")
        ok = False

    # File size sanity (template is ~143K; CloudExplorer is smaller due to removals)
    min_size = 80000 if name != 'CloudExplorer' else 60000
    if len(html) < min_size:
        print(f"  \u2717 {name}: suspiciously small ({len(html):,} chars)")
        ok = False

    # Key JS markers must be present (CloudExplorer keeps these in JS even though modal HTML is gone)
    markers = ['sessionSnapshots', 'FOLLOWUP_MAP', 'CE_TEMPLATE_PROMPTS', 'CE_FAMILY_PROMPTS']
    if name != 'CloudExplorer':
        markers.append('fwModalOverlay')
    for marker in markers:
        if marker not in html:
            print(f"  \u2717 {name}: missing marker '{marker}'")
            ok = False

    # Page-specific markers
    if f'body.page = "{name}";' not in html:
        print(f"  \u2717 {name}: body.page not set correctly")
        ok = False

    # CloudExplorer should NOT have assess panel HTML
    if name == 'CloudExplorer':
        if 'id="assessPanel"' in html:
            print(f"  \u2717 {name}: assess panel HTML should be removed")
            ok = False
        if 'id="navAssessment"' in html:
            print(f"  \u2717 {name}: Run Assessment nav button should be removed")
            ok = False
    else:
        # Assessment pages must have assess panel
        if 'id="assessPanel"' not in html:
            print(f"  \u2717 {name}: missing assess panel")
            ok = False

    # No leftover DataSecurity references (except in CE_TEMPLATE/FAMILY which are generic)
    html_section = '\n'.join(html.split('\n')[:800])
    if 'Data Security' in html_section and name != 'DataSecurity':
        before_ce = html_section.split('<div class="ce-panel-list">')[0] if '<div class="ce-panel-list">' in html_section else html_section
        if 'Data Security' in before_ce:
            print(f"  ! {name}: possible stale 'Data Security' reference in HTML section")

    return ok


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    template_path = WEBAPP / "DataSecurity.html"
    if not template_path.exists():
        print(f"ERROR: Template not found: {template_path}")
        sys.exit(1)

    template = template_path.read_text(encoding="utf-8")
    print(f"Template: DataSecurity.html ({len(template):,} chars, {template.count(chr(10))+1} lines)")

    # Verify template div balance first
    t_opens = template.count('<div')
    t_closes = template.count('</div>')
    print(f"  Template divs: {t_opens} opens / {t_closes} closes")
    if t_opens != t_closes:
        print("  WARNING: Template itself has div imbalance!")

    all_ok = True
    for page_id, cfg in PAGES.items():
        html = generate(template, cfg)
        ok = verify(html, page_id)
        if not ok:
            print(f"FAIL: {page_id} failed verification!")
            all_ok = False
            continue

        out_path = WEBAPP / f"{page_id}.html"
        out_path.write_text(html, encoding="utf-8")
        divs = html.count('<div')
        lines = html.count('\n') + 1
        print(f"\u2713 {page_id}.html ({len(html):,} chars, {lines} lines, {divs}/{html.count('</div>')} divs)")

    if not all_ok:
        print("\nSome pages failed verification. Check errors above.")
        sys.exit(1)
    else:
        print(f"\nDone! All {len(PAGES)} pages generated successfully.")
        # Verify PostureIQ and DataSecurity are untouched
        for protected in ["SecurityComplianceAssessment.html", "DataSecurity.html"]:
            p = WEBAPP / protected
            if p.exists():
                print(f"  {protected}: {len(p.read_text(encoding='utf-8')):,} chars (unchanged)")


if __name__ == "__main__":
    main()
