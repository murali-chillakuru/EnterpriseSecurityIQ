#!/usr/bin/env python3
"""
Build the PostureIQ Deep-Dive Technical Reference HTML presentation.

Uses html_template_generator.py from CustomClaimsProvider/tools.

Usage:
    python Technical-Docs/build_deep_dive.py
"""

import sys
from pathlib import Path

# Import the generator
_GEN_DIR = Path(r"c:\Users\mchillakuru\#GitHubMyrepos\CustomClaimsProvider\tools")
sys.path.insert(0, str(_GEN_DIR))
from html_template_generator import generate_html, render_table, render_callout, render_code_block


# ════════════════════════════════════════════════════════════════
#  SHORTHAND HELPERS
# ════════════════════════════════════════════════════════════════

def _tbl(headers, rows):
    return render_table(headers, rows)

def _info(txt):
    return render_callout("info", txt)

def _warn(txt):
    return render_callout("warning", txt)

def _danger(txt):
    return render_callout("danger", txt)

def _success(txt):
    return render_callout("success", txt)

def _code(txt):
    return render_code_block(txt)


# ════════════════════════════════════════════════════════════════
#  SLIDE CONTENT — SLIDE 1: WHAT IS THIS REPO
# ════════════════════════════════════════════════════════════════

SLIDE1_HTML = f"""
<p><strong>PostureIQ</strong> (repo name: <code>EnterpriseSecurityIQ</code>) is an
<strong>AI-powered security posture assessment platform</strong> for Microsoft Azure
and Microsoft Entra ID. It performs <em>strictly read-only</em> audits of your entire
tenant — subscriptions, Entra directory, Microsoft 365 services — and maps every
finding to one or more compliance frameworks.</p>

<p>The platform ships as a <strong>containerized FastAPI application</strong> that
embeds an OpenAI function-calling agent (GPT-4.1 / GPT-5.1), 68 async evidence
collectors, 10 domain evaluators, and multi-format report generators. It can be
accessed through a web dashboard, Microsoft Teams personal tab, or CLI scripts.</p>

{_tbl(
    ["Dimension", "Detail"],
    [
        ["Language", "Python 3.12 — ~50,000 lines across 70+ modules"],
        ["Agent Framework", "Microsoft Agent Framework SDK (responses v1 protocol)"],
        ["LLM", "Azure OpenAI — GPT-4.1 (primary), GPT-5.1 (fallback)"],
        ["Evidence Sources", "49 Azure ARM/data-plane collectors + 18 Entra/Graph collectors + 1 standalone RBAC"],
        ["Compliance Frameworks", "11 frameworks, 525 controls"],
        ["Assessment Domains", "7 engines: PostureIQ, Risk, Data Security, RBAC, Copilot Readiness, AI Agent Security, Cloud Explorer"],
        ["Report Formats", "HTML, PDF (Chromium), Excel, JSON, Markdown, SARIF, OSCAL"],
        ["Deployment", "Azure Container App on managed identity — fully idempotent PowerShell deploy"],
        ["UI", "11 SPA pages (vanilla JS + MSAL.js v5.6.3) + Teams personal tab with NAA"],
        ["Security", "Read-only (zero write APIs), non-root container, PII summarized, SHA-256 report integrity"],
    ]
)}

{_info("<strong>Key principle:</strong> PostureIQ never modifies your tenant. All Azure ARM and MS Graph calls are GET/LIST only. No PUT, POST, PATCH, or DELETE operations are ever issued against customer resources.")}
"""


# ════════════════════════════════════════════════════════════════
#  SLIDE 2: HOW IT HELPS
# ════════════════════════════════════════════════════════════════

SLIDE2_STEPS = [
    {
        "number": 1,
        "title": "Eliminates Manual Security Audits",
        "content_html": """
<p>Traditional security assessments require weeks of manual evidence gathering across Azure Portal,
Entra admin center, and Defender dashboards. PostureIQ automates this entirely — 68 collectors
harvest <strong>218 evidence types</strong> in under 5 minutes, covering resources you might miss manually.</p>
""" + _tbl(
    ["Manual Approach", "PostureIQ Approach"],
    [
        ["Weeks of portal navigation", "Automated collection in &lt;5 minutes"],
        ["Inconsistent evidence gathering", "218 standardized evidence types"],
        ["Point-in-time snapshots", "Repeatable, deterministic assessments"],
        ["Subjective severity ratings", "Algorithmic risk scoring (0–100)"],
    ]
),
    },
    {
        "number": 2,
        "title": "Multi-Framework Compliance Mapping",
        "content_html": """
<p>A single assessment run maps findings to <strong>all 11 compliance frameworks simultaneously</strong>.
No need to run separate audits for FedRAMP, PCI-DSS, and ISO 27001 — PostureIQ evaluates once
and cross-references 525 controls across all frameworks.</p>
""" + _tbl(
    ["Framework", "Controls", "Focus"],
    [
        ["NIST 800-53 Rev 5", "83", "Federal information systems"],
        ["FedRAMP Moderate", "69", "Cloud services for US government"],
        ["CIS Azure Benchmark v2.0", "53", "Azure-specific hardening"],
        ["MCSB (Microsoft Cloud Security Benchmark)", "53", "Microsoft cloud best practices"],
        ["PCI DSS v4.0", "51", "Payment card data security"],
        ["ISO 27001:2022", "51", "International information security"],
        ["SOC 2 Type II", "47", "Service organization controls"],
        ["HIPAA Security Rule", "43", "Healthcare data protection"],
        ["NIST CSF", "29", "Cybersecurity framework"],
        ["CSA CCM", "24", "Cloud controls matrix"],
        ["GDPR", "22", "EU data protection"],
    ]
),
    },
    {
        "number": 3,
        "title": "Prioritized, AI-Powered Remediation",
        "content_html": """
<p>Every finding is scored using <code>severity × exploitability × blast_radius</code> to produce
a <strong>RiskScore (0–100)</strong>. Findings are then ranked by ROI = risk / √effort, surfacing
<strong>quick wins</strong> that deliver maximum security improvement for minimum effort.</p>
<p>For the top-15 highest-risk findings, the AI agent generates <strong>ready-to-run remediation scripts</strong>
(Azure CLI / PowerShell / Terraform) tailored to your specific resource configuration.</p>
""",
    },
    {
        "number": 4,
        "title": "Attack Path Detection",
        "content_html": """
<p>PostureIQ detects <strong>9 cross-domain attack path patterns</strong> that individual findings alone
would not reveal:</p>
<ul>
<li>Privilege escalation chains (e.g., over-permissioned SP → Key Vault → production secrets)</li>
<li>Lateral movement paths (e.g., weak NSG → compute → managed identity → storage)</li>
<li>Conditional Access bypass routes</li>
<li>Network pivot opportunities</li>
<li>Credential theft chains</li>
</ul>
""",
    },
    {
        "number": 5,
        "title": "Executive & Technical Reporting",
        "content_html": """
<p>Reports are generated in <strong>7 formats</strong> for different audiences:</p>
""" + _tbl(
    ["Format", "Audience", "Content"],
    [
        ["HTML Dashboard", "Security team", "Interactive charts, drill-down findings, remediation scripts"],
        ["PDF", "Executives / auditors", "Print-ready compliance report via Playwright Chromium"],
        ["Excel", "Analysts", "Filterable worksheets with all findings and evidence"],
        ["JSON", "Automation / CI-CD", "Machine-readable for pipeline gates (<code>--fail-on-severity</code>)"],
        ["SARIF", "DevSecOps", "Static analysis format for IDE integration"],
        ["OSCAL", "Federal compliance", "NIST Open Security Controls Assessment Language"],
        ["Markdown", "Documentation", "Embeddable in wikis and READMEs"],
    ]
),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 3: CAPABILITIES & FEATURES
# ════════════════════════════════════════════════════════════════

SLIDE3_STEPS = [
    {
        "number": 1,
        "title": "7 Assessment Engines",
        "content_html": _tbl(
            ["#", "Engine", "Agent Tool", "CLI Script", "Evaluators", "Key Focus"],
            [
                ["1", "<strong>PostureIQ</strong>", "<code>run_postureiq_assessment</code>", "—", "18 modules", "10 security domains, 113 checks, attack paths, AI fixes"],
                ["2", "<strong>Risk Analysis</strong>", "<code>analyze_risk</code>", "<code>run_risk_analysis.py</code>", "8 modules", "Identity, Network, Defender, Config, Insider Risk"],
                ["3", "<strong>Data Security</strong>", "<code>assess_data_security</code>", "<code>run_data_security.py</code>", "32 modules", "39 categories, ~140 checks (storage, DB, encryption)"],
                ["4", "<strong>RBAC</strong>", "<code>generate_rbac_report</code>", "<code>run_rbac_report.py</code>", "8 modules", "Hierarchy tree, PIM, group expansion, risk flags"],
                ["5", "<strong>Copilot Readiness</strong>", "<code>assess_copilot_readiness</code>", "<code>run_copilot_readiness.py</code>", "16 modules", "Oversharing, labels, DLP, access governance, shadow AI"],
                ["6", "<strong>AI Agent Security</strong>", "<code>assess_ai_agent_security</code>", "<code>run_ai_agent_security.py</code>", "14 modules", "Copilot Studio, Foundry, Custom AI, Entra AI"],
                ["7", "<strong>Cloud Explorer</strong>", "<code>search_tenant</code>", "<code>run_query.py</code>", "8 modules", "NL→KQL, 50+ ARG templates, Entra queries"],
            ]
        ),
    },
    {
        "number": 2,
        "title": "14 AI Agent Tools",
        "content_html": """
<p>The OpenAI function-calling agent exposes 14 tools, each dispatched via <code>TOOL_MAP</code> in <code>agent.py</code>:</p>
""" + _tbl(
            ["Tool", "Category", "Purpose"],
            [
                ["<code>run_postureiq_assessment</code>", "Assessment", "Full posture assessment with framework selection"],
                ["<code>analyze_risk</code>", "Assessment", "Risk gap analysis across 5 domains"],
                ["<code>assess_data_security</code>", "Assessment", "Data security evaluation (39 categories)"],
                ["<code>generate_rbac_report</code>", "Assessment", "RBAC hierarchy and risk analysis"],
                ["<code>assess_copilot_readiness</code>", "Assessment", "M365 Copilot readiness evaluation"],
                ["<code>assess_ai_agent_security</code>", "Assessment", "AI agent security across 6 platforms"],
                ["<code>search_tenant</code>", "Query", "NL→KQL against Azure Resource Graph + Entra"],
                ["<code>query_results</code>", "Query", "Query previous assessment results"],
                ["<code>search_exposure</code>", "Query", "Search for specific exposure patterns"],
                ["<code>check_permissions</code>", "Utility", "Verify ARM + Graph access before assessment"],
                ["<code>compare_runs</code>", "Analysis", "Delta comparison between assessment runs"],
                ["<code>query_assessment_history</code>", "History", "Browse historical assessment data"],
                ["<code>generate_report</code>", "Report", "Generate reports from existing results"],
                ["<code>generate_custom_report</code>", "Report", "Custom report with user-specified sections"],
            ]
        ),
    },
    {
        "number": 3,
        "title": "68 Async Evidence Collectors",
        "content_html": """
<p>Collectors are auto-discovered via a <code>@register_collector</code> decorator pattern in <code>collectors/registry.py</code>.
They run in parallel batches (Azure: 12 concurrent, Entra: 9 concurrent) with retry, pagination, and graceful
<code>AccessDenied</code> handling.</p>
""" + _tbl(
            ["Source", "Count", "Examples"],
            [
                ["Azure ARM (control plane)", "~40", "compute, network, storage, databases, AKS, Key Vault, Defender, policy, diagnostics, monitoring"],
                ["Azure Data Plane", "~9", "ACR repos, Cosmos DB collections, APIM backends, Key Vault secrets/certificates, Storage blob configs"],
                ["Entra / MS Graph", "~13", "Users, groups, roles, conditional access, PIM, risk policies, applications, workload identity"],
                ["M365 Compliance", "~5", "Sensitivity labels, DLP policies, SharePoint/OneDrive, Purview"],
                ["Standalone", "~1", "RBAC assignment collector (separate pipeline)"],
            ]
        ) + _info("<strong>Evidence types:</strong> Each collector produces typed evidence records indexed by <code>EvidenceType</code> enum — total of 218 distinct evidence types across all collectors."),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 4: END USER EXPERIENCE
# ════════════════════════════════════════════════════════════════

SLIDE4_STEPS = [
    {
        "number": 1,
        "title": "Security Administrator / Engineer",
        "content_html": """
<p>The primary user. Opens the web dashboard or Teams tab, authenticates via Microsoft SSO, and runs assessments through the chat interface.</p>
<ul>
<li><strong>Run assessments</strong> — type "Run a PostureIQ assessment against FedRAMP" → full automated audit</li>
<li><strong>Explore findings</strong> — drill into specific domains, view attack paths, read remediation scripts</li>
<li><strong>Query the tenant</strong> — "Show me all storage accounts without private endpoints" → NL→KQL via Cloud Explorer</li>
<li><strong>Compare runs</strong> — "Compare this assessment with last week's" → delta report showing drift</li>
<li><strong>Download reports</strong> — HTML, PDF, Excel, SARIF for integration with existing workflows</li>
</ul>
""",
    },
    {
        "number": 2,
        "title": "CISO / Security Leadership",
        "content_html": """
<p>Receives executive-level reports with compliance percentages, maturity levels, and trend analysis.</p>
<ul>
<li><strong>Executive dashboard</strong> — compliance % per framework, domain maturity radar chart</li>
<li><strong>PDF reports</strong> — print-ready for board presentations and audit committees</li>
<li><strong>Trend tracking</strong> — score history across assessment runs shows improvement trajectory</li>
<li><strong>Attack path summary</strong> — high-level view of critical cross-domain risks</li>
</ul>
""",
    },
    {
        "number": 3,
        "title": "Compliance Officer / Auditor",
        "content_html": """
<p>Uses PostureIQ to prepare for audits and demonstrate framework compliance.</p>
<ul>
<li><strong>Framework-specific reports</strong> — select FedRAMP, PCI-DSS, HIPAA, etc. for targeted assessment</li>
<li><strong>Evidence catalog</strong> — complete inventory of collected evidence with SHA-256 integrity hashes</li>
<li><strong>OSCAL export</strong> — NIST-standard format accepted by federal audit tools</li>
<li><strong>SARIF export</strong> — integrates with compliance scanning pipelines</li>
<li><strong>Methodology report</strong> — documents the assessment approach for auditor review</li>
</ul>
""",
    },
    {
        "number": 4,
        "title": "DevOps / Platform Engineer",
        "content_html": """
<p>Integrates PostureIQ into CI/CD pipelines and manages the platform infrastructure.</p>
<ul>
<li><strong>CI/CD gate mode</strong> — <code>--fail-on-severity critical</code> blocks deployment on critical findings</li>
<li><strong>JSON output</strong> — machine-readable results for automated processing</li>
<li><strong>CLI scripts</strong> — <code>run_*.py</code> scripts for headless execution in pipelines</li>
<li><strong>Infrastructure management</strong> — <code>deploy.ps1</code> and <code>redeploy-image.ps1</code> for updates</li>
</ul>
""",
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 5: REPORT GENERATION FLOW (Sequence Diagram)
# ════════════════════════════════════════════════════════════════

REPORT_FLOW_DIAGRAM = {
    "type": "diagram",
    "id": "reportFlow",
    "title": "Report Generation Flow — Behind the Scenes",
    "subtitle": "What happens when a user clicks 'Run Assessment' in the dashboard",
    "default_desc": "This animated sequence shows the complete end-to-end flow from user click through evidence collection, evaluation, report generation, and delivery.",
    "actors": [
        {"name": "User", "icon": "👤", "sub": "Browser", "tag": "External", "tag_class": "external"},
        {"name": "SPA", "icon": "🖥️", "sub": "MSAL.js", "tag": "Client", "tag_class": "onprem"},
        {"name": "FastAPI", "icon": "⚙️", "sub": "Port 8088", "tag": "Cloud", "tag_class": "cloud"},
        {"name": "OpenAI", "icon": "🧠", "sub": "GPT-4.1", "tag": "Cloud", "tag_class": "cloud"},
        {"name": "Engine", "icon": "🔍", "sub": "Evaluators", "tag": "Cloud", "tag_class": "cloud"},
        {"name": "Azure", "icon": "☁️", "sub": "ARM+Graph", "tag": "Cloud", "tag_class": "cloud"},
        {"name": "Blob", "icon": "💾", "sub": "Storage", "tag": "Cloud", "tag_class": "cloud"},
    ],
    "steps": [
        {
            "from": 0, "to": 1,
            "label": "Run Assessment",
            "title": "1. User Initiates Assessment",
            "desc": "User types a request like <em>'Run PostureIQ assessment against FedRAMP and NIST 800-53'</em> in the chat panel and clicks Send.",
            "details": "<p>The chat interface accepts natural language. The user can specify:</p><ul><li>Which engine to run (PostureIQ, Data Security, Risk, etc.)</li><li>Which frameworks to evaluate against</li><li>Specific focus areas or subscriptions</li></ul><p>The SPA captures the message and prepares to send it along with pre-acquired OAuth tokens.</p>"
        },
        {
            "from": 1, "to": 1,
            "label": "MSAL acquireToken",
            "title": "2. Token Acquisition via MSAL.js",
            "desc": "SPA silently acquires two OAuth tokens via MSAL.js — one for <code>Microsoft Graph</code> and one for <code>Azure Management</code>.",
            "details": "<p>Two separate <code>acquireTokenSilent()</code> calls:</p><ul><li><strong>Graph token</strong>: scopes = <code>User.Read, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, AuditLog.Read.All</code></li><li><strong>ARM token</strong>: scope = <code>https://management.azure.com/user_impersonation</code></li></ul><p>In Teams: uses Nested App Auth (NAA) via <code>createNestablePublicClientApplication()</code> for cookie-less token brokering.</p><p>Silent token refresh succeeds as long as the user has an active SSO session. Falls back to popup on failure.</p>"
        },
        {
            "from": 1, "to": 2,
            "label": "POST /chat (SSE)",
            "title": "3. SSE Request to FastAPI",
            "desc": "SPA opens a Server-Sent Events connection to <code>POST /chat</code>, sending the user message plus both OAuth tokens in the request body.",
            "details": "<p>Request body:</p><pre style='font-size:11px;background:#1e1e1e;color:#d4d4d4;padding:8px;border-radius:4px;'>{\"message\": \"Run PostureIQ against FedRAMP\",\n \"graph_token\": \"eyJ0eXAi...\",\n \"arm_token\": \"eyJ0eXAi...\",\n \"page\": \"SecurityComplianceAssessment\",\n \"conversation_id\": \"abc-123\"}</pre><p>The <code>page</code> field determines which tools are available (page-level tool isolation). The <code>conversation_id</code> enables session state tracking.</p>"
        },
        {
            "from": 2, "to": 2,
            "label": "Validate + Build Context",
            "title": "4. Request Validation & Context Setup",
            "desc": "FastAPI validates tokens, extracts tenant ID from ARM JWT <code>tid</code> claim, creates <code>UserTokenCredential</code>, builds session context, and applies page-level tool isolation.",
            "details": "<p>Steps performed:</p><ol><li>Decode ARM JWT → extract <code>tid</code> (tenant ID), <code>oid</code> (user ID)</li><li>Create <code>UserTokenCredential</code> wrapping both tokens</li><li>Set <code>_request_creds</code> context variable for downstream collectors</li><li>Load session state (previous results if any)</li><li>Build tool schema subset based on <code>PAGE_ALLOWED_TOOLS[page]</code></li><li>Strip already-completed assessment tools from schema (session-duplicate guard)</li><li>Inject <code>SYSTEM_PROMPT</code> + session context summary into messages</li></ol>"
        },
        {
            "from": 2, "to": 3,
            "label": "Chat Completion + Tools",
            "title": "5. OpenAI Function-Calling Request",
            "desc": "FastAPI sends chat completion request to Azure OpenAI with the SYSTEM_PROMPT, user message, and filtered tool schemas. Uses <code>gpt-4.1</code> primary model.",
            "details": "<p>The request includes:</p><ul><li><code>SYSTEM_PROMPT</code> (~2000 tokens) defining PostureIQ's persona, capabilities, and output formatting rules</li><li>Session context summary (existing results, if any)</li><li>User message</li><li>14 tool schemas (filtered by page + session state)</li></ul><p>On <code>RateLimitError</code>: automatically falls back to <code>gpt-5.1</code>.<br>On <code>context_length_exceeded</code>: auto-trims to fit.</p>"
        },
        {
            "from": 3, "to": 2,
            "label": "tool_call: run_postureiq",
            "title": "6. LLM Returns Tool Call",
            "desc": "OpenAI responds with a <code>tool_calls</code> array — e.g., <code>run_postureiq_assessment({frameworks: ['FedRAMP', 'NIST-800-53']})</code>. FastAPI dispatches via <code>TOOL_MAP</code>.",
        },
        {
            "from": 2, "to": 4,
            "label": "Dispatch to Engine",
            "title": "7. Assessment Engine Invocation",
            "desc": "The agent function runs <code>_auto_preflight()</code> to verify ARM/Graph access, then dispatches to the PostureIQ orchestrator which coordinates collectors → evaluators → reports.",
            "details": "<p>Preflight checks:</p><ul><li>ARM: verify subscription list access</li><li>Graph: verify <code>Directory.Read.All</code> scope</li><li>Entra roles: verify Security Reader</li></ul><p>If permissions are missing, returns a clear error listing which permissions to grant — does NOT proceed with partial access.</p>"
        },
        {
            "from": 4, "to": 5,
            "label": "64 Async Collectors",
            "title": "8. Evidence Collection from Azure & Entra",
            "desc": "68 registered collectors run in parallel batches (Azure: 12 concurrent, Entra: 9 concurrent) using the user's delegated tokens. Each collector retries 3× with exponential backoff.",
            "details": "<p>Collection phases:</p><ol><li><strong>Azure ARM collectors</strong> (49): resource inventory, compute, network, storage, databases, security, policy, diagnostics, monitoring, AI services</li><li><strong>Entra/Graph collectors</strong> (18): users, groups, roles, conditional access, PIM, risk policies, applications, workload identity, audit logs</li></ol><p>Each collector produces typed <code>EvidenceRecord</code> objects with deterministic UUID5 identifiers. Access-denied errors are captured gracefully — the assessment continues with available evidence.</p>"
        },
        {
            "from": 5, "to": 4,
            "label": "218 Evidence Types",
            "title": "9. Evidence Returned & Indexed",
            "desc": "Azure ARM and MS Graph APIs return evidence data. The engine normalizes all records into 218 typed evidence types indexed by <code>EvidenceType</code> enum for O(1) lookup.",
        },
        {
            "from": 4, "to": 4,
            "label": "Evaluate → Score → Paths",
            "title": "10. Evaluation Pipeline",
            "desc": "10 domain evaluators run 113 check functions against the evidence index. Findings are mapped to 525 framework controls, scored by severity × exploitability × blast_radius, and analyzed for 9 attack path patterns.",
            "details": "<p>Pipeline stages:</p><ol><li><strong>Domain evaluation</strong>: 10 evaluators (access, identity, data_protection, logging, network, governance, incident_response, change_management, business_continuity, asset_management) run 113 check functions</li><li><strong>Cross-domain fallback</strong>: if primary domain returns <code>not_assessed</code>, tries the owning domain</li><li><strong>Framework mapping</strong>: each finding maps to controls across all selected frameworks</li><li><strong>Risk scoring</strong>: <code>severity_weight × exploitability_factor × blast_radius → RiskScore 0–100</code></li><li><strong>Attack paths</strong>: 9 cross-domain pattern detectors (privilege escalation, lateral movement, CA bypass, etc.)</li><li><strong>Priority ranking</strong>: <code>ROI = risk / √effort</code> → identifies quick wins</li><li><strong>AI fix recommendations</strong>: GPT generates remediation scripts for top-15 findings</li></ol>"
        },
        {
            "from": 4, "to": 2,
            "label": "Findings + Reports",
            "title": "11. Reports Generated & Returned",
            "desc": "19 report generators produce HTML dashboard, PDF, Excel, JSON, Markdown, SARIF, and OSCAL outputs. All files written to <code>/agent/output/{timestamp}/</code> with SHA-256 integrity hashes.",
        },
        {
            "from": 2, "to": 6,
            "label": "Upload Reports",
            "title": "12. Persist to Azure Blob Storage",
            "desc": "The entire output directory is uploaded to <code>esiqnewstorage/reports/{tenant_id}/{timestamp}/</code> via <code>blob_store.py</code>. Assessment metadata saved to history index.",
        },
        {
            "from": 2, "to": 3,
            "label": "Tool result → Summary",
            "title": "13. LLM Generates Response Summary",
            "desc": "FastAPI sends the tool execution result back to OpenAI. The LLM generates a user-friendly Markdown summary with compliance scores, key findings, and download links.",
        },
        {
            "from": 3, "to": 2,
            "label": "Markdown response",
            "title": "14. LLM Returns Final Response",
            "desc": "OpenAI returns a formatted Markdown response summarizing the assessment results, including scores, top findings, and clickable report download links.",
        },
        {
            "from": 2, "to": 1,
            "label": "SSE → Render",
            "title": "15. Streamed to User Browser",
            "desc": "FastAPI streams the response token-by-token via SSE. The SPA renders Markdown in real-time, displays follow-up chip buttons for drill-down, and shows report download links.",
        },
    ],
    "legend": [
        {"label": "Client-side", "class": "primary"},
        {"label": "Server-side", "class": "secondary"},
        {"label": "External APIs", "class": "tertiary"},
    ],
}


# ════════════════════════════════════════════════════════════════
#  SLIDE 6: INFRASTRUCTURE DEPLOYMENT FLOW (Sequence Diagram)
# ════════════════════════════════════════════════════════════════

INFRA_FLOW_DIAGRAM = {
    "type": "diagram",
    "id": "infraFlow",
    "title": "Infrastructure Deployment Flow — Behind the Scenes",
    "subtitle": "What happens when an admin runs deploy.ps1 to create the PostureIQ infrastructure",
    "default_desc": "This animated sequence shows the 16-step idempotent deployment from bare Azure subscription to a running PostureIQ instance.",
    "actors": [
        {"name": "Admin", "icon": "👤", "sub": "PowerShell", "tag": "Operator", "tag_class": "admin"},
        {"name": "deploy.ps1", "icon": "📜", "sub": "16 Steps", "tag": "Script", "tag_class": "builder"},
        {"name": "Azure CLI", "icon": "⌨️", "sub": "az commands", "tag": "Tool", "tag_class": "onprem"},
        {"name": "Azure ARM", "icon": "☁️", "sub": "Resource Mgr", "tag": "Cloud", "tag_class": "cloud"},
        {"name": "Container", "icon": "🐳", "sub": "App Runtime", "tag": "Cloud", "tag_class": "cloud"},
    ],
    "steps": [
        {
            "from": 0, "to": 1,
            "label": "./deploy.ps1",
            "title": "1. Admin Executes Deployment Script",
            "desc": "Admin runs <code>deploy.ps1</code> with optional parameters: <code>$BaseName</code> (default: ESIQNew), <code>$Location</code> (swedencentral), <code>$PrimaryModel</code> (gpt-4.1), <code>$FallbackModel</code> (gpt-5.1).",
            "details": "<p>All resource names are derived from <code>$BaseName</code>:</p><pre style='font-size:11px;background:#1e1e1e;color:#d4d4d4;padding:8px;border-radius:4px;'>$RG = \"ESIQNew-RG\"\n$AIName = \"ESIQNew-AI\"\n$StorageName = \"esiqnewstorage\"\n$KVName = \"ESIQNew-kv\"\n$ACRName = \"esiqnewacr\"\n$IDName = \"ESIQNew-identity\"\n$EnvName = \"ESIQNew-env\"\n$AppName = \"esiqnew-agent\"</pre>"
        },
        {
            "from": 1, "to": 2,
            "label": "az group create",
            "title": "2. Create Resource Group",
            "desc": "Creates <code>ESIQNew-RG</code> in <code>swedencentral</code>. All subsequent resources are scoped to this group.",
        },
        {
            "from": 1, "to": 3,
            "label": "REST PUT AIServices",
            "title": "3. Create AI Foundry Resource + Project",
            "desc": "Creates <code>ESIQNew-AI</code> (CognitiveServices/accounts, kind=AIServices, S0) with custom domain, then creates <code>ESIQNew-project</code> as a child project via ARM REST API.",
            "details": "<p>Two-phase creation:</p><ol><li><code>az cognitiveservices account create --kind AIServices --sku S0</code></li><li>ARM REST PATCH to enable <code>allowProjectManagement: true</code></li><li>ARM REST PUT to create project: <code>{AIId}/projects/ESIQNew-project</code></li></ol><p>The project appears in the AI Foundry portal at <code>ai.azure.com</code>. On startup, the agent self-registers via the Assistants API.</p>"
        },
        {
            "from": 1, "to": 2,
            "label": "Deploy Models",
            "title": "4. Deploy GPT-4.1 and GPT-5.1 Models",
            "desc": "Deploys two OpenAI models under the AI resource: <code>gpt-4.1</code> (primary, 30K TPM) and <code>gpt-5.1</code> (fallback, 30K TPM), both Standard SKU.",
        },
        {
            "from": 1, "to": 2,
            "label": "Create Storage + KV + Logs",
            "title": "5. Create Supporting Resources",
            "desc": "Creates Storage Account (<code>esiqnewstorage</code>, Standard_LRS) with <code>reports</code> blob container, Key Vault (<code>ESIQNew-kv</code>, RBAC auth), Log Analytics workspace, and Application Insights.",
        },
        {
            "from": 1, "to": 2,
            "label": "Create ACR + Identity",
            "title": "6. Create Container Registry & Managed Identity",
            "desc": "Creates <code>esiqnewacr</code> (Basic SKU) for container images and <code>ESIQNew-identity</code> (user-assigned managed identity) for workload authentication.",
        },
        {
            "from": 2, "to": 3,
            "label": "RBAC + Graph API",
            "title": "7. Assign RBAC Roles & Graph Permissions",
            "desc": "Assigns 6 Azure RBAC roles to the managed identity and configures MS Graph application permissions (8 scopes). Graph permissions require Global Admin consent.",
            "details": "<p><strong>Azure RBAC roles:</strong></p><ul><li><code>AcrPull</code> → Container Registry</li><li><code>Reader</code> → Subscription</li><li><code>Security Reader</code> → Subscription</li><li><code>Cognitive Services OpenAI User</code> → AI resource</li><li><code>Azure AI Developer</code> → AI resource</li><li><code>Storage Blob Data Contributor</code> → Storage Account</li></ul><p><strong>MS Graph API permissions (Application):</strong></p><ul><li><code>Directory.Read.All</code>, <code>Policy.Read.All</code>, <code>RoleManagement.Read.All</code></li><li><code>User.Read.All</code>, <code>AuditLog.Read.All</code>, <code>UserAuthenticationMethod.Read.All</code></li><li><code>IdentityRiskyUser.Read.All</code>, <code>Application.Read.All</code></li></ul>"
        },
        {
            "from": 1, "to": 2,
            "label": "Create CA Env + App",
            "title": "8. Create Container Apps Environment & Application",
            "desc": "Creates Container Apps Environment (<code>ESIQNew-env</code>) in <code>northeurope</code> linked to Log Analytics, then creates the Container App (<code>esiqnew-agent</code>) with 1 vCPU, 2 GiB RAM, port 8088, external ingress.",
            "details": "<p>Container App configuration:</p><pre style='font-size:11px;background:#1e1e1e;color:#d4d4d4;padding:8px;border-radius:4px;'>cpu: 1.0, memory: 2Gi\ntargetPort: 8088\ningress: external (HTTPS)\nminReplicas: 1, maxReplicas: 1\nidentity: ESIQNew-identity\nregistry: esiqnewacr.azurecr.io</pre><p>Environment variables set: <code>AZURE_OPENAI_ENDPOINT</code>, <code>AZURE_OPENAI_DEPLOYMENT</code>, <code>FOUNDRY_PROJECT_ENDPOINT</code>, <code>AZURE_CLIENT_ID</code>, <code>AZURE_TENANT_ID</code>, <code>REPORT_STORAGE_ACCOUNT</code>, etc.</p>"
        },
        {
            "from": 2, "to": 4,
            "label": "Build + Deploy Image",
            "title": "9. ACR Build & Container Deployment",
            "desc": "Builds the Docker image via ACR Tasks (<code>az acr build</code>) and deploys to the Container App. The Dockerfile uses multi-stage build with non-root <code>appuser</code>.",
        },
        {
            "from": 1, "to": 2,
            "label": "Register Entra App",
            "title": "10. Create App Registration for Dashboard SSO",
            "desc": "Creates <code>ESIQNew-Dashboard</code> Entra app registration with SPA platform, multi-org audience, redirect URIs for localhost and the Container App FQDN. Configures <code>access_as_user</code> API scope.",
        },
        {
            "from": 1, "to": 4,
            "label": "Patch + Rebuild",
            "title": "11. Patch Webapp with MSAL Config & Rebuild",
            "desc": "Replaces <code>YOUR-CLIENT-ID-HERE</code> and <code>YOUR-TENANT-ID-HERE</code> placeholders in webapp HTML files with actual values, then rebuilds and redeploys the container image.",
        },
        {
            "from": 4, "to": 4,
            "label": "Startup → Register Agent",
            "title": "12. Container Starts & Registers Foundry Agent",
            "desc": "On startup, <code>api.py</code> creates an <code>AsyncAzureOpenAI</code> client and registers/finds an OpenAI Assistant named <code>'EnterpriseSecurityIQ'</code> via the Assistants API — making it visible in the AI Foundry portal.",
        },
    ],
    "legend": [
        {"label": "Admin / Script", "class": "primary"},
        {"label": "Azure Resources", "class": "secondary"},
        {"label": "Container Runtime", "class": "tertiary"},
    ],
}


# ════════════════════════════════════════════════════════════════
#  SLIDE 7: AZURE INFRASTRUCTURE DEEP-DIVE
# ════════════════════════════════════════════════════════════════

SLIDE7_STEPS = [
    {
        "number": 1,
        "title": "Resource Group — ESIQNew-RG",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Name", "<code>ESIQNew-RG</code>"],
                ["Location", "<code>swedencentral</code>"],
                ["Subscription", "AI (<code>d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0</code>)"],
                ["Purpose", "Logical container for all PostureIQ resources"],
                ["Resource Count", "14 resources"],
            ]
        ),
    },
    {
        "number": 2,
        "title": "AI Foundry Resource — ESIQNew-AI",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Type", "<code>Microsoft.CognitiveServices/accounts</code>"],
                ["Kind", "<code>AIServices</code> (S0 tier)"],
                ["Custom Domain", "<code>esiqnew-ai</code> → <code>https://esiqnew-ai.cognitiveservices.azure.com/</code>"],
                ["Features", "allowProjectManagement enabled, OpenAI model hosting"],
                ["Models Hosted", "gpt-4.1 (Standard, 30K TPM) + gpt-5.1 (Standard, 30K TPM)"],
                ["Used By", "Container App via managed identity for chat completions + Assistants API"],
            ]
        ) + _info("The AI resource also hosts the <strong>Foundry Project</strong> (<code>ESIQNew-project</code>), making the agent visible in the AI Foundry portal at <code>ai.azure.com</code>."),
    },
    {
        "number": 3,
        "title": "Storage Account — esiqnewstorage",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Type", "<code>Microsoft.Storage/storageAccounts</code>"],
                ["SKU", "Standard_LRS (locally redundant)"],
                ["Kind", "StorageV2"],
                ["TLS", "1.2 minimum"],
                ["Containers", "<code>reports</code> — stores all generated assessment reports"],
                ["Auth", "Managed identity with <code>Storage Blob Data Contributor</code> role"],
                ["Used By", "<code>blob_store.py</code> for report persistence, <code>evidence_history.py</code> for assessment history"],
            ]
        ),
    },
    {
        "number": 4,
        "title": "Key Vault — ESIQNew-kv",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Type", "<code>Microsoft.KeyVault/vaults</code>"],
                ["Auth Model", "RBAC (not access policies)"],
                ["Purge Protection", "Enabled"],
                ["Purpose", "Secure storage for secrets and certificates (future use)"],
            ]
        ),
    },
    {
        "number": 5,
        "title": "Observability — Log Analytics + Application Insights",
        "content_html": _tbl(
            ["Resource", "Name", "Configuration"],
            [
                ["Log Analytics Workspace", "<code>ESIQNew-law</code>", "PerGB2018 pricing, retention: 30 days (default)"],
                ["Application Insights", "<code>ESIQNew-appinsights</code>", "Workspace-based (linked to LAW)"],
            ]
        ) + """<p>Container Apps Environment is linked to Log Analytics for automatic container log collection.
Application Insights provides application-level telemetry, request tracing, and dependency tracking.</p>""",
    },
    {
        "number": 6,
        "title": "Container Registry — esiqnewacr",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Type", "<code>Microsoft.ContainerRegistry/registries</code>"],
                ["SKU", "Basic"],
                ["Purpose", "Hosts PostureIQ Docker images (<code>esiqnew-agent:vNN</code>)"],
                ["Build", "ACR Tasks (<code>az acr build</code>) — builds run in Azure, not locally"],
                ["Auth", "Managed identity with <code>AcrPull</code> role for Container App"],
            ]
        ),
    },
    {
        "number": 7,
        "title": "Managed Identity — ESIQNew-identity",
        "content_html": """
<p>User-assigned managed identity used by the Container App for all Azure and Graph API operations.</p>
""" + _tbl(
            ["Attribute", "Value"],
            [
                ["Client ID", "<code>d5d10273-4a8b-4251-9b9d-00fe035df97a</code>"],
                ["Principal ID", "<code>d742617c-...</code>"],
            ]
        ) + """<p><strong>RBAC Roles:</strong></p>""" + _tbl(
            ["Role", "Scope", "Purpose"],
            [
                ["AcrPull", "Container Registry", "Pull container images"],
                ["Reader", "Subscription", "List resources across subscriptions"],
                ["Security Reader", "Subscription", "Access Defender and security data"],
                ["Cognitive Services OpenAI User", "AI Resource", "Call OpenAI chat completions"],
                ["Azure AI Developer", "AI Resource", "Register Foundry agents"],
                ["Storage Blob Data Contributor", "Storage Account", "Upload/download reports"],
            ]
        ) + """<p><strong>MS Graph API Permissions (Application):</strong></p>
<p><code>Directory.Read.All</code>, <code>Policy.Read.All</code>, <code>RoleManagement.Read.All</code>,
<code>User.Read.All</code>, <code>AuditLog.Read.All</code>, <code>UserAuthenticationMethod.Read.All</code>,
<code>IdentityRiskyUser.Read.All</code>, <code>Application.Read.All</code></p>""",
    },
    {
        "number": 8,
        "title": "Container Apps Environment & Application",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Environment", "<code>ESIQNew-env</code> (northeurope)"],
                ["App Name", "<code>esiqnew-agent</code>"],
                ["FQDN", "<code>esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io</code>"],
                ["CPU / Memory", "1.0 vCPU / 2 GiB RAM / 4 GiB ephemeral storage"],
                ["Port", "8088 (external HTTPS ingress)"],
                ["Replicas", "min: 1, max: 1 (no auto-scale currently)"],
                ["Identity", "<code>ESIQNew-identity</code> (user-assigned)"],
                ["Registry", "<code>esiqnewacr.azurecr.io</code> (managed identity auth)"],
                ["Volume", "<code>/agent/output</code> → Azure File share <code>esiqreports</code>"],
                ["Region", "northeurope (swedencentral failed — AKS capacity issue)"],
            ]
        ) + _warn("<strong>Note:</strong> Container Apps are in <code>northeurope</code> while other resources are in <code>swedencentral</code> due to an <code>AKSCapacityHeavyUsage</code> limitation during initial deployment."),
    },
    {
        "number": 9,
        "title": "App Registration — ESIQNew-Dashboard",
        "content_html": _tbl(
            ["Property", "Value"],
            [
                ["Type", "Entra App Registration (SPA platform)"],
                ["Audience", "Multi-organization (<code>AzureADMultipleOrgs</code>)"],
                ["Redirect URIs", "<code>http://localhost:8088</code>, <code>https://{FQDN}</code>"],
                ["API Scope", "<code>api://{appId}/access_as_user</code>"],
                ["Pre-authorized Clients", "7 Microsoft first-party clients (Teams, Office, Outlook)"],
                ["Purpose", "Enables MSAL.js SSO in the web dashboard and Teams personal tab"],
            ]
        ),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 8: CONTAINER APP CONFIGURATION
# ════════════════════════════════════════════════════════════════

SLIDE8_STEPS = [
    {
        "number": 1,
        "title": "Environment Variables",
        "content_html": _tbl(
            ["Variable", "Value", "Purpose"],
            [
                ["<code>AZURE_OPENAI_ENDPOINT</code>", "<code>https://esiqnew-ai.cognitiveservices.azure.com/</code>", "AI Foundry endpoint for chat completions"],
                ["<code>AZURE_OPENAI_DEPLOYMENT</code>", "<code>gpt-4.1</code>", "Primary model deployment name"],
                ["<code>AZURE_OPENAI_FALLBACK_DEPLOYMENT</code>", "<code>gpt-5.1</code>", "Fallback model on rate limit"],
                ["<code>AZURE_OPENAI_API_VERSION</code>", "<code>2025-01-01-preview</code>", "API version for OpenAI calls"],
                ["<code>FOUNDRY_PROJECT_ENDPOINT</code>", "<code>https://esiqnew-ai.services.ai.azure.com/api/projects/ESIQNew-project</code>", "Foundry project for agent registration"],
                ["<code>AZURE_CLIENT_ID</code>", "<code>d5d10273-...</code>", "Managed identity client ID"],
                ["<code>AZURE_TENANT_ID</code>", "<code>4a3eb5f4-...</code>", "Entra tenant ID"],
                ["<code>REPORT_STORAGE_ACCOUNT</code>", "<code>esiqnewstorage</code>", "Blob storage for report persistence"],
                ["<code>REPORT_STORAGE_CONTAINER</code>", "<code>reports</code>", "Blob container name"],
            ]
        ),
    },
    {
        "number": 2,
        "title": "Dockerfile & Container Security",
        "content_html": """
<ul>
<li><strong>Base image:</strong> Python 3.12 slim</li>
<li><strong>Non-root user:</strong> Runs as <code>appuser</code> (not root)</li>
<li><strong>No secrets in image:</strong> All credentials via managed identity at runtime</li>
<li><strong>Playwright Chromium:</strong> Installed for PDF report generation via headless browser</li>
<li><strong>Multi-stage build:</strong> Dependencies installed in builder stage, copied to runtime</li>
</ul>
""",
    },
    {
        "number": 3,
        "title": "API Endpoints",
        "content_html": _tbl(
            ["Method", "Path", "Auth", "Purpose"],
            [
                ["GET", "<code>/</code>", "None", "Serves webapp SPA (static files from <code>webapp/</code>)"],
                ["POST", "<code>/chat</code>", "graph_token + arm_token", "SSE-streamed agent chat with function-calling loop"],
                ["POST", "<code>/assessments</code>", "graph_token + arm_token", "Background assessment execution"],
                ["GET", "<code>/assessments/{id}</code>", "None", "Poll assessment status"],
                ["GET", "<code>/health</code>", "None", "Health check (liveness/readiness)"],
                ["GET", "<code>/reports/{path}</code>", "None", "Serve generated report files"],
            ]
        ) + _info("<strong>Rate limiting:</strong> 20 <code>/chat</code> requests per 60s per IP, 5 <code>/assessments</code> per 60s per IP."),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 9: AUTHENTICATION & SECURITY
# ════════════════════════════════════════════════════════════════

SLIDE9_STEPS = [
    {
        "number": 1,
        "title": "User Authentication (MSAL.js SSO)",
        "content_html": """
<p>The web dashboard uses <strong>MSAL.js v5.6.3</strong> for Microsoft SSO authentication. On page load, it attempts silent token acquisition; on failure, presents a login button.</p>
<p>Two tokens are acquired per session:</p>
""" + _tbl(
            ["Token", "Scopes", "Used For"],
            [
                ["Graph Token", "<code>User.Read, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All</code>", "Entra/Graph data collection"],
                ["ARM Token", "<code>https://management.azure.com/user_impersonation</code>", "Azure resource data collection"],
            ]
        ) + """<p>Both tokens are sent with every <code>/chat</code> request. The backend wraps them in a <code>UserTokenCredential</code> that routes
each SDK call to the appropriate token based on the requested scope.</p>""",
    },
    {
        "number": 2,
        "title": "Managed Identity Authentication",
        "content_html": """
<p>The Container App uses <code>DefaultAzureCredential</code> with the user-assigned managed identity for:</p>
<ul>
<li>OpenAI API calls (via <code>get_bearer_token_provider</code> for <code>cognitiveservices.azure.com</code>)</li>
<li>Blob Storage operations (upload/download reports)</li>
<li>Foundry Agent registration (Assistants API)</li>
</ul>
<p>For assessments, the system uses <strong>user-delegated tokens</strong> (from the SPA) rather than the managed identity.
This ensures assessments run with the <em>user's actual permissions</em>, not elevated service-level access.</p>
""",
    },
    {
        "number": 3,
        "title": "Security Controls",
        "content_html": _tbl(
            ["Control", "Implementation"],
            [
                ["Read-only operations", "All ARM and Graph calls are GET/LIST only — no write APIs"],
                ["Rate limiting", "20 chat + 5 assessment requests per minute per IP"],
                ["CORS whitelist", "Only <code>teams.microsoft.com</code>, <code>*.cloud.microsoft</code>, <code>*.office.com</code>, <code>localhost</code>"],
                ["CSP frame-ancestors", "Allows Teams iframe embedding only from Microsoft domains"],
                ["Token validation", "ARM JWT decoded to extract <code>tid</code> (tenant) and <code>oid</code> (user)"],
                ["SSRF protection", "<code>_validate_webhook_url()</code> rejects private/loopback/link-local IPs, enforces HTTPS"],
                ["PII handling", "User data summarized as counts only — never exported in full"],
                ["Non-root container", "Runs as <code>appuser</code>, no secrets baked into image"],
                ["Report integrity", "SHA-256 hashes on all generated reports"],
                ["Session isolation", "Per-conversation state via <code>contextvars.ContextVar</code>"],
                ["Page-level tool isolation", "Each SPA page can only invoke its relevant assessment tools"],
                ["Session-duplicate guard", "Prevents re-running assessments on follow-up questions in same session"],
            ]
        ),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 10: ASSESSMENT ENGINES DETAIL
# ════════════════════════════════════════════════════════════════

SLIDE10_STEPS = [
    {
        "number": 1,
        "title": "PostureIQ Engine (Core)",
        "content_html": """
<p>The flagship engine — performs a comprehensive security posture assessment across 10 domains, mapping findings to all 11 compliance frameworks.</p>
""" + _tbl(
            ["Component", "Detail"],
            [
                ["Evaluator Modules", "18 (10 domain evaluators + engine, plugins, suppressions, remediation, attack_paths, priority_ranking, ai_fix_recommendations)"],
                ["Check Functions", "113 individual security checks"],
                ["Domains", "Access, Identity, Data Protection, Logging, Network, Governance, Incident Response, Change Management, Business Continuity, Asset Management"],
                ["Scoring", "Severity-weighted: critical=4, high=3, medium=2, low=1 — with partial credit"],
                ["Risk Formula", "<code>severity_weight × exploitability × blast_radius × 100 / max</code>"],
                ["Attack Paths", "9 cross-domain patterns (privilege escalation, lateral movement, CA bypass, network pivot, etc.)"],
                ["AI Fixes", "GPT-generated remediation scripts for top-15 findings"],
                ["Reports", "19 generators (HTML dashboard, PDF, Excel, JSON, MD, SARIF, OSCAL, executive dashboard, evidence catalog, methodology, delta, drift)"],
            ]
        ),
    },
    {
        "number": 2,
        "title": "Risk Analysis Engine",
        "content_html": """
<p>Gap analysis focused on 5 risk domains with actionable remediation plans.</p>
""" + _tbl(
            ["Domain", "Focus Areas"],
            [
                ["Identity Risk", "MFA gaps, stale accounts, privileged role sprawl, risky sign-ins"],
                ["Network Risk", "NSG misconfigurations, missing private endpoints, public-facing services"],
                ["Defender Risk", "Disabled Defender plans, unmonitored resources, alert suppression"],
                ["Configuration Risk", "Policy non-compliance, missing diagnostics, untagged resources"],
                ["Insider Risk", "Oversharing, excessive permissions, audit log gaps"],
            ]
        ),
    },
    {
        "number": 3,
        "title": "Data Security Engine",
        "content_html": """
<p>The most comprehensive engine with 32 evaluator modules covering 39 data security categories.</p>
""" + _tbl(
            ["Category Group", "Modules"],
            [
                ["Storage & Encryption", "storage, encryption, keyvault, backup_dr"],
                ["Databases", "database, cosmosdb, postgres_mysql, redis, sql_detailed"],
                ["Network & Access", "private_endpoints, network_segmentation, data_access, identity_access, managed_identity"],
                ["M365 & Compliance", "m365_dlp, m365_lifecycle, dlp_alerts, sharepoint, purview, data_classification"],
                ["Platform Services", "containers, messaging, ai_services, data_factory, file_sync, platform_services"],
                ["Advanced", "advanced_analytics, threat_detection, data_residency"],
            ]
        ),
    },
    {
        "number": 4,
        "title": "RBAC Analysis Engine",
        "content_html": """
<p>Builds a complete hierarchy tree of Azure RBAC assignments with risk analysis.</p>
<ul>
<li><strong>Tree Builder:</strong> Constructs management group → subscription → resource group → resource hierarchy</li>
<li><strong>Principal Resolver:</strong> Resolves users, groups (with nested member expansion), service principals</li>
<li><strong>Risk Detection:</strong> Flags over-privileged accounts, stale assignments, Owner/Contributor sprawl, missing PIM activation</li>
<li><strong>Deterministic IDs:</strong> UUID5-based finding IDs for repeatable output</li>
</ul>
""",
    },
    {
        "number": 5,
        "title": "Copilot Readiness Engine",
        "content_html": """
<p>Evaluates organizational readiness for Microsoft 365 Copilot deployment across 10 categories:</p>
""" + _tbl(
            ["Category", "What It Checks"],
            [
                ["Oversharing", "Broadly shared sites, open permissions, guest access to sensitive content"],
                ["Sensitivity Labels", "Label coverage, auto-labeling policies, DLP integration"],
                ["DLP Policies", "Policy coverage, rule effectiveness, endpoint DLP"],
                ["Restricted Search", "SharePoint restricted content discoverability settings"],
                ["Access Governance", "Access reviews, lifecycle policies, entitlement management"],
                ["Content Lifecycle", "Retention policies, disposition review, records management"],
                ["Audit & Monitoring", "Unified audit log, alert policies, compliance center"],
                ["Zero Trust", "Conditional Access, device compliance, identity protection"],
                ["Shadow AI", "Unsanctioned AI tool usage, data leakage risks"],
                ["Copilot Security", "Copilot-specific security settings, plugin governance"],
            ]
        ),
    },
    {
        "number": 6,
        "title": "AI Agent Security Engine",
        "content_html": """
<p>Assesses security posture of AI agent deployments across 6 platforms:</p>
""" + _tbl(
            ["Platform", "Evaluator Modules", "Focus"],
            [
                ["Copilot Studio", "copilot_studio, copilot_studio_ext, copilot_studio_dlp", "Bot security, DLP policies, connector governance"],
                ["AI Foundry", "foundry_infra, foundry_ext, foundry_new", "Model security, endpoint auth, data handling"],
                ["Custom AI", "custom_ai", "Custom-built AI applications and endpoints"],
                ["Entra AI", "entra_ai", "AI identity and access management"],
                ["AI Infrastructure", "ai_infra", "GPU clusters, model serving, network isolation"],
                ["AI Defense", "ai_defense", "Prompt injection protection, content safety, jailbreak detection"],
            ]
        ),
    },
    {
        "number": 7,
        "title": "Cloud Explorer Engine",
        "content_html": """
<p>Natural language query interface for Azure Resource Graph and Entra ID.</p>
<ul>
<li><strong>NL → KQL Dispatcher:</strong> Translates natural language to Azure Resource Graph KQL queries</li>
<li><strong>50+ ARG Templates:</strong> Pre-built queries for common resource searches (grouped by family: storage, compute, network, identity, security, etc.)</li>
<li><strong>Entra Queries:</strong> User, group, role, application, and conditional access lookups</li>
<li><strong>Evidence Search:</strong> Search previously collected evidence by keyword or type</li>
<li><strong>Cross-Reference:</strong> Correlate resources across subscriptions and resource types</li>
</ul>
""",
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 11: COLLECTOR & EVALUATOR ARCHITECTURE
# ════════════════════════════════════════════════════════════════

SLIDE11_STEPS = [
    {
        "number": 1,
        "title": "Collector Architecture",
        "content_html": """
<p>Collectors follow a <strong>plugin auto-discovery pattern</strong> using decorators and module scanning.</p>
""" + _code("""@register_collector(name="cosmos_db", plane="control", source="azure")
async def collect_azure_cosmos(creds, subscriptions):
    # ... collect Cosmos DB configuration evidence
    return [make_evidence("CosmosDB", "cosmos_accounts", data)]""") + """
<p><strong>Registry mechanism:</strong> <code>registry.py</code> uses <code>pkgutil.iter_modules</code> to auto-import
all modules under <code>collectors/azure/</code> and <code>collectors/entra/</code>. Each <code>@register_collector</code>
decorator registers the function with metadata (name, plane, source, priority).</p>
<p><strong>Base collector features</strong> (<code>base.py</code>):</p>
<ul>
<li>3 retries with exponential backoff (2s, 4s, 8s)</li>
<li><code>AccessDeniedError</code> — captures 401/403 as missing-permission findings (doesn't fail)</li>
<li><code>paginate_graph()</code> — pages through MS Graph collections with 429 throttling</li>
<li><code>paginate_arm()</code> — iterates ARM async pagers with 429 handling</li>
<li>Shared resource inventory cache (<code>inventory.py</code>) to avoid duplicate ARM calls</li>
</ul>
""",
    },
    {
        "number": 2,
        "title": "Azure Collectors (49 Modules)",
        "content_html": _tbl(
            ["Category", "Modules", "Evidence Types"],
            [
                ["Core Resources", "resources, compute, network, storage", "Resource inventory, VMs, NICs, NSGs, Storage Accounts"],
                ["Security", "security, defender_plans, defender_advanced, sentinel", "Defender plans, alerts, Sentinel workspaces"],
                ["Identity & Access", "rbac, rbac_collector, policy, policy_compliance", "Role assignments, Azure Policy, compliance states"],
                ["Databases", "databases, sql_detailed, rdbms_detailed, cosmosdb_data_plane", "SQL/Cosmos/PostgreSQL/MySQL configurations"],
                ["Networking", "network_expanded, app_gateway, frontdoor_cdn, dns", "Load balancers, Front Door, DNS zones"],
                ["Containers & Apps", "containers, functions, webapp_detailed, aks_in_cluster", "AKS, App Service, Functions, ACR"],
                ["Monitoring", "monitoring, diagnostics, activity_logs, cost_billing", "Log Analytics, diagnostic settings, activity logs"],
                ["AI & ML", "ai_services, ai_content_safety, ml_cognitive, copilot_studio, foundry_config", "AI model deployments, content safety policies"],
                ["Data Platform", "data_analytics, messaging, managed_disks, redis_iot_logic, batch_aci", "Event Hubs, Service Bus, Data Factory"],
                ["Compliance", "m365_compliance, m365_sensitivity_labels, purview_dlp, sharepoint_onedrive", "DLP policies, sensitivity labels, SharePoint"],
                ["Data Plane", "storage_data_plane, acr_data_plane, apim_data_plane", "Blob configs, ACR repos, APIM backends"],
            ]
        ),
    },
    {
        "number": 3,
        "title": "Entra / Graph Collectors (18 Modules)",
        "content_html": _tbl(
            ["Module", "MS Graph Scopes", "Evidence Types"],
            [
                ["users, user_details", "<code>User.Read.All</code>", "User profiles, MFA status, last sign-in"],
                ["roles", "<code>RoleManagement.Read.All</code>", "Directory roles, role assignments, PIM eligible"],
                ["conditional_access", "<code>Policy.Read.All</code>", "CA policies, named locations, auth strengths"],
                ["applications, workload_identity", "<code>Application.Read.All</code>", "App registrations, service principals, federated creds"],
                ["identity_protection, risk_policies", "<code>IdentityRiskyUser.Read.All</code>", "Risky users, risk detections, risk policies"],
                ["governance", "<code>Directory.Read.All</code>", "Access reviews, entitlement management, lifecycle"],
                ["audit_logs", "<code>AuditLog.Read.All</code>", "Sign-in logs, audit events, suspicious activity"],
                ["security_policies, tenant", "<code>Policy.Read.All</code>", "Security defaults, cross-tenant, org settings"],
                ["ai_identity", "<code>Application.Read.All</code>", "AI-related service principals and app configs"],
            ]
        ),
    },
    {
        "number": 4,
        "title": "Evaluator Scoring Algorithm",
        "content_html": """
<p>The PostureIQ evaluator uses a <strong>severity-weighted scoring algorithm</strong> with partial credit:</p>
""" + _code("""# Severity weights
WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Compliance scoring (per framework)
for control in framework_controls:
    if status == "compliant":     score += WEIGHTS[severity]     # Full credit
    elif status == "partial":     score += WEIGHTS[severity] * 0.5  # Half credit
    elif status == "non_compliant": score += 0                     # Zero
    # missing_evidence / not_assessed → excluded from denominator

compliance_pct = (score / max_possible_score) * 100""") + """
<p><strong>Risk scoring</strong> per finding:</p>
""" + _code("""risk_score = severity_weight * exploitability * blast_radius * 100 / max_score

# Exploitability factors (0.3 - 1.0):
#   check_mfa_enforcement = 0.95 (very exploitable)
#   check_private_endpoint_adoption = 1.0 (fully exposed)

# Blast radius by domain (0.3 - 1.0):
#   identity = 1.0, access = 0.9, network = 0.8, data_protection = 0.7

# Risk tiers: Critical (≥75), High (≥50), Medium (≥25), Low (<25)""") + """
<p><strong>Priority ranking:</strong> <code>ROI = risk_score / √effort</code> — surfaces quick wins with maximum security impact for minimum remediation effort.</p>
""",
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 12: WEBAPP & TEAMS INTEGRATION
# ════════════════════════════════════════════════════════════════

SLIDE12_STEPS = [
    {
        "number": 1,
        "title": "Web Dashboard — 11 SPA Pages",
        "content_html": _tbl(
            ["Page", "File", "Purpose"],
            [
                ["Portal", "<code>index.html</code>", "Card-grid launcher linking to all assessment SPAs"],
                ["PostureIQ", "<code>SecurityComplianceAssessment.html</code>", "Full posture assessment with framework picker"],
                ["Risk Analysis", "<code>RiskAnalysis.html</code>", "Risk gap analysis interface"],
                ["Data Security", "<code>DataSecurity.html</code>", "Data security assessment"],
                ["RBAC Report", "<code>RBACReport.html</code>", "RBAC hierarchy analysis"],
                ["Copilot Readiness", "<code>CopilotReadiness.html</code>", "M365 Copilot readiness evaluation"],
                ["AI Agent Security", "<code>AIAgentSecurity.html</code>", "AI agent security assessment"],
                ["Cloud Explorer", "<code>CloudExplorer.html</code>", "NL→KQL query interface"],
                ["PostureIQ Standalone", "<code>PostureIQ.html</code>", "Dedicated PostureIQ page"],
                ["Teams Tab", "<code>Teams-SecurityComplianceAssessment.html</code>", "Teams-embedded version with NAA auth"],
                ["Auth Callbacks", "<code>auth-start.html</code>, <code>auth-end.html</code>", "MSAL authentication flow handlers"],
            ]
        ) + """
<p><strong>UI stack:</strong> Vanilla JavaScript + CSS (no React/Vue/Angular), Fluent 2 / Viva design tokens,
MSAL.js v5.6.3, SSE streaming for real-time chat, sidebar nav with draggable resizer, multi-phase progress
indicator, follow-up chip buttons.</p>
""",
    },
    {
        "number": 2,
        "title": "Microsoft Teams Integration",
        "content_html": """
<p>PostureIQ integrates as a <strong>Teams Personal Tab</strong> using manifest version 1.22 with Nested App Authentication (NAA).</p>
""" + _tbl(
            ["Component", "Detail"],
            [
                ["Manifest Version", "1.22 (required for NAA)"],
                ["App Type", "Personal Tab (static tab, <code>personal</code> scope)"],
                ["Auth Method", "Nested App Auth — cookie-less token brokering through Teams client"],
                ["MSAL Variant", "<code>createNestablePublicClientApplication()</code> — special Teams-aware MSAL client"],
                ["Cache Storage", "<code>localStorage</code> (required — <code>sessionStorage</code> fails on Teams Desktop)"],
                ["Theme Sync", "TeamsJS SDK detects dark/light/high-contrast → maps to <code>data-theme</code> attribute"],
                ["TeamsJS SDK", "v2.31.1"],
                ["Pre-authorized Clients", "7 Microsoft first-party client IDs (Teams, Office, Outlook desktop/web/mobile)"],
            ]
        ) + """
<p><strong>NAA scopes</strong> declared in manifest:</p>
<ul>
<li>Graph: <code>User.Read, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All</code></li>
<li>ARM: <code>https://management.azure.com/user_impersonation</code></li>
</ul>
""",
    },
    {
        "number": 3,
        "title": "Teams App Deployment",
        "content_html": """
<p><code>Deploy-TeamsApp.ps1</code> handles the complete Teams app lifecycle:</p>
""" + _tbl(
            ["Mode", "What It Does"],
            [
                ["<code>Validate</code>", "Parses manifest JSON, checks for unresolved <code>{{placeholders}}</code>, validates required fields and manifest version ≥ 1.17"],
                ["<code>Build</code>", "Resolves <code>{{TEAMS_APP_ID}}</code> and <code>{{BACKEND_FQDN}}</code> placeholders, creates <code>PostureIQ.zip</code> with manifest + icons"],
                ["<code>Sideload</code>", "Uploads the zip to Teams for development testing"],
                ["<code>OrgPublish</code>", "Publishes to the organization's Teams app catalog"],
                ["<code>EntraConfig</code>", "Configures API scope, SPA redirects, pre-authorized clients on the Entra app registration"],
                ["<code>Full</code>", "Runs all phases sequentially"],
            ]
        ),
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 13: CONFIGURATION & SCHEMAS
# ════════════════════════════════════════════════════════════════

SLIDE13_STEPS = [
    {
        "number": 1,
        "title": "Assessment Configuration",
        "content_html": """
<p>Configuration is loaded from environment variable <code>ENTERPRISESECURITYIQ_CONFIG</code> (path to JSON file),
with environment variable overrides taking precedence.</p>
""" + _tbl(
            ["Section", "Key Settings", "Defaults"],
            [
                ["<code>auth</code>", "tenant_id, auth_mode, subscription_filter", "auto mode, all subscriptions"],
                ["<code>collectors</code>", "azure_enabled, entra_enabled, azure_batch_size, entra_batch_size, collector_timeout, user_sample_limit", "true, true, 12, 9, 600s, 200"],
                ["<code>thresholds</code>", "max_subscription_owners, max_privileged_percent, max_global_admins, min_mfa_percent, max_stale_percent, diagnostic_coverage_target", "3, 20%, 5, 90%, 20%, 80%"],
                ["<code>output</code>", "output_formats, output_dir", "[json, html], output/"],
                ["<code>frameworks</code>", "List of frameworks to evaluate", "[FedRAMP]"],
                ["<code>checkpoint</code>", "checkpoint_enabled", "true (resume interrupted assessments)"],
            ]
        ),
    },
    {
        "number": 2,
        "title": "JSON Schemas",
        "content_html": """
<p>Four JSON schemas (draft-07) define the data model:</p>
""" + _tbl(
            ["Schema", "Purpose", "Key Fields"],
            [
                ["<code>evidence-record.json</code>", "Evidence collected from Azure/Entra", "source, collector, evidence_type, description, data, resource_id"],
                ["<code>finding-record.json</code>", "Individual security finding", "control_id, framework, status, severity, domain, description, recommendation"],
                ["<code>compliance-control.json</code>", "Framework control result", "control_id, overall_status, compliant/non_compliant counts, findings"],
                ["<code>report-summary.json</code>", "Assessment summary", "assessment_id, tenant_id, frameworks, compliance_percentage, domain_summaries"],
            ]
        ) + """
<p>All data models use <strong>deterministic UUID5 identifiers</strong> (namespace: <code>c0a80164-dead-beef-cafe-000000000001</code>)
ensuring the same input always produces the same finding ID — critical for delta comparisons and drift detection.</p>
""",
    },
    {
        "number": 3,
        "title": "Data Security Relevance Descriptors",
        "content_html": """
<p><code>config/data-security-relevance.json</code> contains 39 detailed descriptions explaining <em>why</em> each
data security category matters. These are used by the AI agent to provide context-aware explanations in reports.</p>
<p>Example categories: <code>storage_encryption</code>, <code>database_tde</code>, <code>keyvault_access</code>,
<code>private_endpoints</code>, <code>purview_classification</code>, <code>dlp_policies</code>, etc.</p>
""",
    },
]


# ════════════════════════════════════════════════════════════════
#  SLIDE 14: DETERMINISM & QUALITY
# ════════════════════════════════════════════════════════════════

SLIDE14_HTML = f"""
<p>PostureIQ includes <strong>6 determinism validation scripts</strong> that prove the evaluation pipeline produces
<strong>byte-identical outputs</strong> from the same evidence input — critical for compliance audits and delta comparisons.</p>

{_tbl(
    ["Script", "Engine Tested", "Method"],
    [
        ["<code>run_postureiq_determinism_check.py</code>", "PostureIQ (full compliance)", "Collect once → run <code>evaluate_all()</code> 3× → compare FindingIds, scores, controls"],
        ["<code>run_aias_determinism_check.py</code>", "AI Agent Security", "Collect once → run all 50+ analyzers 3× → compare by composite key"],
        ["<code>run_cr_determinism_check.py</code>", "Copilot Readiness", "Same pattern"],
        ["<code>run_ds_determinism_check.py</code>", "Data Security", "Same pattern"],
        ["<code>run_rbac_determinism_check.py</code>", "RBAC", "Same pattern"],
        ["<code>run_risk_determinism_check.py</code>", "Risk Analysis", "Same pattern"],
    ]
)}

<h3 style="margin-top:16px;">Why Determinism Matters</h3>
<ul>
<li><strong>Compliance audits:</strong> Auditors need to verify that re-running the same assessment produces identical results</li>
<li><strong>Delta comparisons:</strong> The <code>compare_runs</code> tool relies on stable FindingIds to detect actual changes vs. noise</li>
<li><strong>Drift detection:</strong> Only real configuration changes should trigger drift alerts, not evaluation randomness</li>
<li><strong>CI/CD gates:</strong> Pipeline gates (<code>--fail-on-severity</code>) must be deterministic to avoid flaky builds</li>
</ul>

<h3 style="margin-top:16px;">How It Works</h3>
<ol>
<li>Evidence is collected <strong>once</strong> and saved to a snapshot</li>
<li>The evaluation pipeline runs <strong>3 times</strong> against the same snapshot</li>
<li>Volatile fields are stripped (<code>EvaluatedAt</code>, timestamps, UUIDs that should be random)</li>
<li>Findings are deterministically sorted by composite key</li>
<li>Full JSON serializations are compared byte-for-byte</li>
<li>Verdict: <strong>PASS ✓</strong> (all runs identical) or <strong>FAIL ✗</strong> (with field-level diff report)</li>
</ol>

{_success("<strong>All 6 engines pass determinism validation</strong> — confirmed across multiple tenant configurations.")}
"""


# ════════════════════════════════════════════════════════════════
#  SLIDE 15: GAPS & RECOMMENDATIONS (with fixes + MS Learn refs)
# ════════════════════════════════════════════════════════════════

SLIDE15_STEPS = [
    {
        "number": 1,
        "title": "GAP: No CI/CD Pipeline",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> No <code>.github/workflows/</code> or <code>azure-pipelines.yml</code> in the repo.
Deployment is entirely manual via <code>deploy.ps1</code> and <code>redeploy-image.ps1</code>.</p>

{_danger("<strong>Risk:</strong> Manual deployments are error-prone, lack audit trails, and don't enforce quality gates (tests, linting, security scanning) before production.")}

<h4>Recommended Fix</h4>
<p>Create a <strong>GitHub Actions workflow</strong> with three stages:</p>
{_code("""# .github/workflows/deploy.yml
name: Build & Deploy PostureIQ
on:
  push:
    branches: [main]
    paths: ['AIAgent/**', 'webapp/**']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -r AIAgent/requirements.txt
      - run: python -m pytest AIAgent/tests/ -v

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with: { creds: ${{{{ secrets.AZURE_CREDENTIALS }}}} }
      - run: az acr build --registry esiqnewacr --image esiqnew-agent:${{{{ github.sha }}}} --file AIAgent/Dockerfile .

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with: { creds: ${{{{ secrets.AZURE_CREDENTIALS }}}} }
      - run: |
          az containerapp update -n esiqnew-agent -g ESIQNew-RG \\
            --image esiqnewacr.azurecr.io/esiqnew-agent:${{{{ github.sha }}}}
          az containerapp revision restart -n esiqnew-agent -g ESIQNew-RG""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/github-actions" target="_blank">Deploy to Azure Container Apps with GitHub Actions</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-registry/container-registry-github-action" target="_blank">Build container images with GitHub Actions and ACR</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure" target="_blank">Connect GitHub and Azure (OIDC / service principal)</a></li>
</ul>
""",
    },
    {
        "number": 2,
        "title": "GAP: No .env.template File",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> The README references <code>cp .env.template .env</code> but no template file exists.
New developers must guess which environment variables are required.</p>

<h4>Recommended Fix</h4>
<p>Create <code>.env.template</code> in the repo root with all required variables documented:</p>
{_code("""# .env.template — Copy to .env and fill in values
# === Azure OpenAI ===
AZURE_OPENAI_ENDPOINT=https://your-resource.cognitiveservices.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4.1
AZURE_OPENAI_FALLBACK_DEPLOYMENT=gpt-5.1
AZURE_OPENAI_API_VERSION=2025-01-01-preview

# === Foundry Project ===
FOUNDRY_PROJECT_ENDPOINT=https://your-resource.services.ai.azure.com/api/projects/your-project

# === Identity ===
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-managed-identity-client-id

# === Storage ===
REPORT_STORAGE_ACCOUNT=your-storage-account
REPORT_STORAGE_CONTAINER=reports

# === Optional ===
ENTERPRISESECURITYIQ_CONFIG=config/enterprisesecurityiq.config.json
ENTERPRISESECURITYIQ_AUTH_MODE=auto
ALLOWED_ORIGINS=http://localhost:8088""")}
""",
    },
    {
        "number": 3,
        "title": "GAP: Single Replica — No Auto-Scaling",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Container App runs with <code>minReplicas: 1, maxReplicas: 1</code>.
No auto-scaling under load; single point of failure if the instance crashes.</p>

{_danger("<strong>Risk:</strong> Long-running assessments (5+ minutes) block the single instance. Concurrent users will experience timeouts.")}

<h4>Recommended Fix</h4>
{_code("""# Update scaling rules
az containerapp update -n esiqnew-agent -g ESIQNew-RG \\
  --min-replicas 1 --max-replicas 3 \\
  --scale-rule-name http-scaling \\
  --scale-rule-type http \\
  --scale-rule-http-concurrency 10""")}

<p>This configures:</p>
<ul>
<li><strong>Minimum 1 replica</strong> — always available, no cold start</li>
<li><strong>Maximum 3 replicas</strong> — scales out under concurrent load</li>
<li><strong>HTTP concurrency trigger</strong> — scales when &gt;10 concurrent requests per replica</li>
</ul>

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/scale-app" target="_blank">Set scaling rules in Azure Container Apps</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/scale-app#http" target="_blank">HTTP scaling rule reference</a></li>
</ul>
""",
    },
    {
        "number": 4,
        "title": "GAP: No VNet Integration",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Container App has external ingress with no VNet. Storage account uses public network access.
All traffic flows over the public internet.</p>

{_danger("<strong>Risk:</strong> Sensitive assessment data (tenant configurations, security findings) traverses the public internet between the Container App and Storage/Key Vault/AI services.")}

<h4>Recommended Fix</h4>
<ol>
<li><strong>Create a VNet</strong> with dedicated subnets for Container Apps, private endpoints, and services</li>
<li><strong>Deploy Container Apps Environment with internal VNet</strong></li>
<li><strong>Add Private Endpoints</strong> for Storage Account, Key Vault, ACR, and AI Services</li>
<li><strong>Disable public network access</strong> on Storage and Key Vault</li>
<li><strong>Add Azure Front Door</strong> as the public-facing entry point (see Gap #7)</li>
</ol>

{_code("""# Create VNet and subnets
az network vnet create -n esiq-vnet -g ESIQNew-RG --address-prefix 10.0.0.0/16
az network vnet subnet create -n container-apps-subnet --vnet-name esiq-vnet \\
  -g ESIQNew-RG --address-prefix 10.0.0.0/23
az network vnet subnet create -n private-endpoints-subnet --vnet-name esiq-vnet \\
  -g ESIQNew-RG --address-prefix 10.0.2.0/24

# Create Container Apps Environment with VNet
az containerapp env create -n ESIQNew-env -g ESIQNew-RG \\
  --infrastructure-subnet-resource-id /subscriptions/.../container-apps-subnet \\
  --internal-only false  # or true if using Front Door

# Add private endpoint for Storage
az network private-endpoint create -n esiq-storage-pe -g ESIQNew-RG \\
  --vnet-name esiq-vnet --subnet private-endpoints-subnet \\
  --private-connection-resource-id /subscriptions/.../esiqnewstorage \\
  --group-id blob --connection-name storage-connection""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom-internal" target="_blank">Provide a virtual network to an internal Container Apps environment</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/networking" target="_blank">Networking in Azure Container Apps</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview" target="_blank">What is Azure Private Endpoint?</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints" target="_blank">Use private endpoints for Azure Storage</a></li>
</ul>
""",
    },
    {
        "number": 5,
        "title": "GAP: No WAF / DDoS Protection",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> The Container App is directly exposed to the internet with only built-in rate limiting (20 req/min).
No Web Application Firewall or DDoS protection.</p>

<h4>Recommended Fix</h4>
<p>Deploy <strong>Azure Front Door Premium</strong> with a WAF policy in front of the Container App:</p>
{_code("""# Create Front Door profile
az afd profile create -n esiq-frontdoor -g ESIQNew-RG --sku Premium_AzureFrontDoor

# Create WAF policy
az network front-door waf-policy create -n esiqwafpolicy -g ESIQNew-RG \\
  --mode Prevention --sku Premium_AzureFrontDoor

# Configure managed rule sets (OWASP + Bot protection)
az network front-door waf-policy managed-rules add -g ESIQNew-RG \\
  --policy-name esiqwafpolicy \\
  --type Microsoft_DefaultRuleSet --version 2.1

# Add origin (Container App)
az afd origin create -n esiq-origin --origin-group-name esiq-origins \\
  --profile-name esiq-frontdoor -g ESIQNew-RG \\
  --host-name esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io \\
  --origin-host-header esiqnew-agent...northeurope.azurecontainerapps.io \\
  --http-port 80 --https-port 443""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview" target="_blank">What is Azure Front Door?</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview" target="_blank">Azure WAF on Azure Front Door</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/waf" target="_blank">Protect Azure Container Apps with WAF on Front Door</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview" target="_blank">Azure DDoS Protection overview</a></li>
</ul>
""",
    },
    {
        "number": 6,
        "title": "GAP: Graph Admin Consent May Be Pending",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> The deploy script assigns MS Graph application permissions to the managed identity,
but <strong>Global Admin consent</strong> may not have been granted. Without consent, Entra collectors will fail with 403 errors.</p>

<h4>Recommended Fix</h4>
<p>Grant admin consent via the Entra admin center or Azure CLI:</p>
{_code("""# Option 1: Via Azure CLI
# Get the managed identity's service principal object ID
$spId = az identity show -n ESIQNew-identity -g ESIQNew-RG --query principalId -o tsv

# Grant admin consent for all assigned Graph permissions
# (Navigate to Entra admin center → Enterprise apps → ESIQNew-identity → Permissions → Grant admin consent)

# Option 2: Via Entra Portal
# 1. Go to https://entra.microsoft.com
# 2. Navigate to: Identity → Applications → Enterprise applications
# 3. Search for the managed identity name or client ID
# 4. Click Permissions → Grant admin consent for [tenant]
# 5. Sign in as Global Administrator and approve""")}

{_warn("<strong>Requires:</strong> Global Administrator or Privileged Role Administrator role in Entra ID.")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent" target="_blank">Grant tenant-wide admin consent to an application</a></li>
<li><a href="https://learn.microsoft.com/en-us/graph/permissions-overview" target="_blank">Overview of Microsoft Graph permissions</a></li>
<li><a href="https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-assign-app-role-managed-identity" target="_blank">Assign app roles to managed identities</a></li>
</ul>
""",
    },
    {
        "number": 7,
        "title": "GAP: No Backup Strategy for Blob Storage",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Storage account <code>esiqnewstorage</code> uses Standard_LRS with no soft delete,
versioning, or lifecycle management configured. Report data could be permanently lost on accidental deletion.</p>

<h4>Recommended Fix</h4>
{_code("""# Enable blob soft delete (14-day retention)
az storage account blob-service-properties update \\
  --account-name esiqnewstorage -g ESIQNew-RG \\
  --enable-delete-retention true --delete-retention-days 14

# Enable container soft delete
az storage account blob-service-properties update \\
  --account-name esiqnewstorage -g ESIQNew-RG \\
  --enable-container-delete-retention true --container-delete-retention-days 14

# Enable blob versioning
az storage account blob-service-properties update \\
  --account-name esiqnewstorage -g ESIQNew-RG \\
  --enable-versioning true

# Create lifecycle management policy (move to cool after 90 days, archive after 365)
az storage account management-policy create --account-name esiqnewstorage -g ESIQNew-RG \\
  --policy @lifecycle-policy.json""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview" target="_blank">Soft delete for blobs</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview" target="_blank">Blob versioning</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/blobs/lifecycle-management-overview" target="_blank">Blob storage lifecycle management</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-backup-and-restore" target="_blank">Operational backup for Azure Blobs</a></li>
</ul>
""",
    },
    {
        "number": 8,
        "title": "GAP: No Disaster Recovery Plan",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Single-region deployment (northeurope for Container App, swedencentral for other resources).
No secondary region, no geo-redundant storage, no failover plan.</p>

<h4>Recommended Fix</h4>
<ol>
<li><strong>Upgrade storage to GRS</strong> (Geo-Redundant Storage) for automatic cross-region replication</li>
<li><strong>Deploy secondary Container App</strong> in a paired region (e.g., westeurope)</li>
<li><strong>Use Azure Front Door</strong> for active-passive traffic routing with health probes</li>
<li><strong>Replicate ACR</strong> using geo-replication (requires Premium SKU)</li>
<li><strong>Document RTO/RPO targets</strong> and test the failover process</li>
</ol>

{_code("""# Upgrade storage to GRS
az storage account update -n esiqnewstorage -g ESIQNew-RG --sku Standard_GRS

# Upgrade ACR to Premium for geo-replication
az acr update -n esiqnewacr -g ESIQNew-RG --sku Premium
az acr replication create -r esiqnewacr -l westeurope""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/disaster-recovery" target="_blank">Disaster recovery guidance for Azure Container Apps</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy" target="_blank">Azure Storage redundancy</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-registry/container-registry-geo-replication" target="_blank">Geo-replication in Azure Container Registry</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/reliability/reliability-azure-container-apps" target="_blank">Reliability in Azure Container Apps</a></li>
</ul>
""",
    },
    {
        "number": 9,
        "title": "GAP: No Custom Domain / Managed Certificate",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> The Container App uses the auto-generated FQDN
<code>esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io</code>.
No custom domain or branded certificate.</p>

<h4>Recommended Fix</h4>
{_code("""# Add custom domain with managed certificate
az containerapp hostname add -n esiqnew-agent -g ESIQNew-RG \\
  --hostname postureiq.yourdomain.com

# Bind managed certificate (free, auto-renewed)
az containerapp hostname bind -n esiqnew-agent -g ESIQNew-RG \\
  --hostname postureiq.yourdomain.com \\
  --environment ESIQNew-env \\
  --validation-method CNAME""")}

<p><strong>Also update:</strong></p>
<ul>
<li>App Registration redirect URIs → add the custom domain</li>
<li>Teams manifest <code>{{{{BACKEND_FQDN}}}}</code> → custom domain</li>
<li>CORS allowed origins → add custom domain</li>
</ul>

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/custom-domains-managed-certificates" target="_blank">Custom domain names and managed certificates in Azure Container Apps</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/container-apps/custom-domains-certificates" target="_blank">Custom domain names and certificates in Azure Container Apps</a></li>
</ul>
""",
    },
    {
        "number": 10,
        "title": "GAP: No Diagnostic Settings on All Resources",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Log Analytics and Application Insights are deployed, but not all resources
have diagnostic settings configured to send logs to the workspace.</p>

<h4>Recommended Fix</h4>
<p>Enable diagnostic settings for <strong>every resource</strong> to route logs to Log Analytics:</p>
{_code("""# Enable diagnostics on Key Vault
az monitor diagnostic-settings create -n kv-diag \\
  --resource /subscriptions/.../ESIQNew-kv \\
  --workspace /subscriptions/.../ESIQNew-law \\
  --logs '[{{"category":"AuditEvent","enabled":true}}]' \\
  --metrics '[{{"category":"AllMetrics","enabled":true}}]'

# Enable diagnostics on Storage Account
az monitor diagnostic-settings create -n storage-diag \\
  --resource /subscriptions/.../esiqnewstorage/blobServices/default \\
  --workspace /subscriptions/.../ESIQNew-law \\
  --logs '[{{"category":"StorageRead","enabled":true}},{{"category":"StorageWrite","enabled":true}}]'

# Enable diagnostics on AI Services
az monitor diagnostic-settings create -n ai-diag \\
  --resource /subscriptions/.../ESIQNew-AI \\
  --workspace /subscriptions/.../ESIQNew-law \\
  --logs '[{{"category":"Audit","enabled":true}},{{"category":"RequestResponse","enabled":true}}]'""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings" target="_blank">Diagnostic settings in Azure Monitor</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs" target="_blank">Azure resource logs</a></li>
<li><a href="https://learn.microsoft.com/en-us/azure/key-vault/general/logging" target="_blank">Azure Key Vault logging</a></li>
</ul>
""",
    },
    {
        "number": 11,
        "title": "GAP: Sparse Test Coverage",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Only 5 test files visible in <code>AIAgent/tests/</code> (determinism checks and dry-run tests).
The README claims 15 files / 1,357 functions but these are not in the current workspace.</p>

<h4>Recommended Fix</h4>
<p>Implement a comprehensive <code>pytest</code> test suite with:</p>
<ul>
<li><strong>Unit tests</strong> for each evaluator module — mock evidence → verify findings</li>
<li><strong>Integration tests</strong> for the collector → evaluator → report pipeline</li>
<li><strong>Snapshot tests</strong> for HTML/JSON report outputs (detect unintended format changes)</li>
<li><strong>API tests</strong> for FastAPI endpoints using <code>httpx.AsyncClient</code></li>
<li><strong>Coverage target:</strong> 80% line coverage with <code>pytest-cov</code></li>
</ul>
{_code("""# Install test dependencies
pip install pytest pytest-asyncio pytest-cov httpx

# Run tests with coverage
python -m pytest AIAgent/tests/ -v --cov=AIAgent/app --cov-report=html

# Fail CI if coverage drops below 80%
python -m pytest AIAgent/tests/ --cov=AIAgent/app --cov-fail-under=80""")}

<p><strong>Microsoft Learn references:</strong></p>
<ul>
<li><a href="https://learn.microsoft.com/en-us/azure/developer/python/testing-tools" target="_blank">Testing tools for Python in Azure</a></li>
</ul>
""",
    },
    {
        "number": 12,
        "title": "GAP: Missing docs/PROMPTS.md Usage Guide",
        "badge_class": "secondary",
        "content_html": f"""
<p><strong>Current state:</strong> Multiple documentation pages reference <code>docs/PROMPTS.md</code> as a usage guide
with example prompts for each assessment tool, but the file does not exist.</p>

<h4>Recommended Fix</h4>
<p>Create <code>docs/PROMPTS.md</code> with example prompts for each tool:</p>
{_code("""# PostureIQ Usage Guide — Example Prompts

## PostureIQ Assessment
- "Run a PostureIQ assessment against FedRAMP and NIST 800-53"
- "Assess my security posture using CIS Azure Benchmark"
- "Run a full compliance assessment against all frameworks"

## Risk Analysis
- "Analyze risk gaps in my Azure environment"
- "What are my top identity risks?"

## Data Security
- "Assess data security for my storage accounts and databases"
- "Check if my Key Vaults are properly secured"

## RBAC Report
- "Generate an RBAC report for my subscriptions"
- "Show me over-privileged accounts"

## Copilot Readiness
- "Assess my organization's readiness for M365 Copilot"
- "Check for oversharing risks before Copilot deployment"

## AI Agent Security
- "Assess security of our Copilot Studio bots"
- "Check AI agent security across all platforms"

## Cloud Explorer
- "Show me all storage accounts without private endpoints"
- "List VMs that are not using managed disks"
- "Find all resources in eastus without tags" """)}
""",
    },
]


# ════════════════════════════════════════════════════════════════
#  ASSEMBLE FULL CONFIG
# ════════════════════════════════════════════════════════════════

config = {
    "title": "PostureIQ — Deep-Dive Technical Reference",
    "top_bar_title": "PostureIQ / Deep-Dive Technical Reference",
    "subtitle": "Complete architecture, infrastructure, and operational documentation — April 2026",

    "teams": [
        {
            "abbr": "PostureIQ",
            "full_name": "AI Security Posture Assessment Platform",
            "role": "The overall platform — 7 assessment engines, 68 collectors, 11 compliance frameworks",
            "color_class": "primary",
        },
        {
            "abbr": "AI Agent",
            "full_name": "FastAPI + OpenAI Function-Calling Agent",
            "role": "Orchestrates assessments via GPT-4.1/5.1 with 14 tool functions",
            "color_class": "secondary",
        },
        {
            "abbr": "Collectors",
            "full_name": "Azure ARM + MS Graph Evidence Gatherers",
            "role": "68 async collectors harvest 218 evidence types from Azure & Entra ID",
            "color_class": "tertiary",
        },
        {
            "abbr": "Evaluators",
            "full_name": "Domain-Specific Assessment Engines",
            "role": "10 domain evaluators analyze evidence against 525 compliance controls",
            "color_class": "primary",
        },
    ],

    "toc": [
        {"slide": 0, "label": "Title & Overview", "dot_class": "diagram"},
        {"type": "group_label", "slide": -1, "label": "Understanding PostureIQ"},
        {"slide": 1, "label": "What Is This Repo", "dot_class": "primary"},
        {"slide": 2, "label": "How It Helps", "dot_class": "primary",
         "sub_items": [
             {"num": "1", "label": "Automated Audits", "step_id": "step-1"},
             {"num": "2", "label": "Multi-Framework", "step_id": "step-2"},
             {"num": "3", "label": "AI Remediation", "step_id": "step-3"},
             {"num": "4", "label": "Attack Paths", "step_id": "step-4"},
             {"num": "5", "label": "Reporting", "step_id": "step-5"},
         ]},
        {"slide": 3, "label": "Capabilities & Features", "dot_class": "primary"},
        {"slide": 4, "label": "End User Experience", "dot_class": "primary"},
        {"type": "group_label", "slide": -1, "label": "Behind the Scenes"},
        {"slide": 5, "label": "▶ Report Generation Flow", "dot_class": "diagram"},
        {"slide": 6, "label": "▶ Infra Deployment Flow", "dot_class": "diagram"},
        {"type": "group_label", "slide": -1, "label": "Infrastructure"},
        {"slide": 7, "label": "Azure Resources", "dot_class": "secondary",
         "sub_items": [
             {"num": "1", "label": "Resource Group", "step_id": "step-1"},
             {"num": "2", "label": "AI Foundry", "step_id": "step-2"},
             {"num": "3", "label": "Storage", "step_id": "step-3"},
             {"num": "7", "label": "Managed Identity", "step_id": "step-7"},
             {"num": "8", "label": "Container App", "step_id": "step-8"},
         ]},
        {"slide": 8, "label": "Container App Config", "dot_class": "secondary"},
        {"slide": 9, "label": "Auth & Security", "dot_class": "secondary"},
        {"type": "group_label", "slide": -1, "label": "Engines & Code"},
        {"slide": 10, "label": "Assessment Engines", "dot_class": "tertiary"},
        {"slide": 11, "label": "Collectors & Evaluators", "dot_class": "tertiary"},
        {"slide": 12, "label": "Webapp & Teams", "dot_class": "tertiary"},
        {"slide": 13, "label": "Config & Schemas", "dot_class": "tertiary"},
        {"slide": 14, "label": "Determinism & Quality", "dot_class": "tertiary"},
        {"type": "group_label", "slide": -1, "label": "Recommendations"},
        {"slide": 15, "label": "Gaps & Fixes (12)", "dot_class": "ref",
         "sub_items": [
             {"num": "1", "label": "No CI/CD", "step_id": "step-1"},
             {"num": "2", "label": "No .env.template", "step_id": "step-2"},
             {"num": "3", "label": "No Auto-Scaling", "step_id": "step-3"},
             {"num": "4", "label": "No VNet", "step_id": "step-4"},
             {"num": "5", "label": "No WAF/DDoS", "step_id": "step-5"},
             {"num": "6", "label": "Graph Consent", "step_id": "step-6"},
             {"num": "7", "label": "No Blob Backup", "step_id": "step-7"},
             {"num": "8", "label": "No DR Plan", "step_id": "step-8"},
             {"num": "9", "label": "No Custom Domain", "step_id": "step-9"},
             {"num": "10", "label": "No Diagnostics", "step_id": "step-10"},
             {"num": "11", "label": "Test Coverage", "step_id": "step-11"},
             {"num": "12", "label": "Missing PROMPTS.md", "step_id": "step-12"},
         ]},
    ],

    "slides": [
        # ── Slide 0: Title ──
        {
            "type": "title",
            "title": "PostureIQ — Deep-Dive Technical Reference",
            "subtitle": "Complete architecture, infrastructure, and operational documentation — April 2026",
            "teams": [
                {"abbr": "PostureIQ", "full_name": "AI Security Posture Assessment Platform",
                 "role": "The overall platform — 7 assessment engines, 68 collectors, 11 compliance frameworks", "color_class": "primary"},
                {"abbr": "AI Agent", "full_name": "FastAPI + OpenAI Function-Calling Agent",
                 "role": "Orchestrates assessments via GPT-4.1/5.1 with 14 tool functions", "color_class": "secondary"},
                {"abbr": "Collectors", "full_name": "Azure ARM + MS Graph Evidence Gatherers",
                 "role": "68 async collectors harvest 218 evidence types from Azure & Entra ID", "color_class": "tertiary"},
                {"abbr": "Evaluators", "full_name": "Domain-Specific Assessment Engines",
                 "role": "10 domain evaluators analyze evidence against 525 compliance controls", "color_class": "primary"},
            ],
            "title_toc_items": [
                {"label": "What Is This Repo", "slide": 1, "icon_class": "primary", "icon_text": "1"},
                {"label": "How It Helps", "slide": 2, "icon_class": "primary", "icon_text": "2"},
                {"label": "Report Generation Flow", "slide": 5, "icon_class": "diagram", "icon_text": "▶"},
                {"label": "Infra Deployment Flow", "slide": 6, "icon_class": "diagram", "icon_text": "▶"},
                {"label": "Azure Resources Deep-Dive", "slide": 7, "icon_class": "secondary", "icon_text": "☁"},
                {"label": "Assessment Engines", "slide": 10, "icon_class": "tertiary", "icon_text": "🔍"},
                {"label": "Collectors & Evaluators", "slide": 11, "icon_class": "tertiary", "icon_text": "⚙"},
                {"label": "Gaps & Fixes (12)", "slide": 15, "icon_class": "ref", "icon_text": "⚠"},
            ],
        },

        # ── Slide 1: What Is This Repo ──
        {"type": "content", "title": "What Is This Repo?", "content_html": SLIDE1_HTML},

        # ── Slide 2: How It Helps ──
        {
            "type": "phase",
            "label": "How PostureIQ Helps",
            "color_class": "primary",
            "steps": SLIDE2_STEPS,
        },

        # ── Slide 3: Capabilities & Features ──
        {
            "type": "phase",
            "label": "Capabilities & Features",
            "color_class": "primary",
            "steps": SLIDE3_STEPS,
        },

        # ── Slide 4: End User Experience ──
        {
            "type": "phase",
            "label": "End User Experience — By Persona",
            "color_class": "primary",
            "steps": SLIDE4_STEPS,
        },

        # ── Slide 5: Report Generation Flow (Sequence Diagram) ──
        REPORT_FLOW_DIAGRAM,

        # ── Slide 6: Infra Deployment Flow (Sequence Diagram) ──
        INFRA_FLOW_DIAGRAM,

        # ── Slide 7: Azure Infrastructure Deep-Dive ──
        {
            "type": "phase",
            "label": "Azure Infrastructure — All 14 Resources",
            "color_class": "secondary",
            "steps": SLIDE7_STEPS,
        },

        # ── Slide 8: Container App Configuration ──
        {
            "type": "phase",
            "label": "Container App Configuration",
            "color_class": "secondary",
            "steps": SLIDE8_STEPS,
        },

        # ── Slide 9: Authentication & Security ──
        {
            "type": "phase",
            "label": "Authentication & Security",
            "color_class": "secondary",
            "steps": SLIDE9_STEPS,
        },

        # ── Slide 10: Assessment Engines Detail ──
        {
            "type": "phase",
            "label": "Assessment Engines — All 7 Engines",
            "color_class": "tertiary",
            "steps": SLIDE10_STEPS,
        },

        # ── Slide 11: Collector & Evaluator Architecture ──
        {
            "type": "phase",
            "label": "Collector & Evaluator Architecture",
            "color_class": "tertiary",
            "steps": SLIDE11_STEPS,
        },

        # ── Slide 12: Webapp & Teams Integration ──
        {
            "type": "phase",
            "label": "Webapp & Teams Integration",
            "color_class": "tertiary",
            "steps": SLIDE12_STEPS,
        },

        # ── Slide 13: Configuration & Schemas ──
        {
            "type": "phase",
            "label": "Configuration & Schemas",
            "color_class": "tertiary",
            "steps": SLIDE13_STEPS,
        },

        # ── Slide 14: Determinism & Quality ──
        {"type": "content", "title": "Determinism & Quality Assurance", "content_html": SLIDE14_HTML},

        # ── Slide 15: Gaps & Recommendations ──
        {
            "type": "phase",
            "label": "Gaps & Recommended Fixes — With Microsoft Learn References",
            "color_class": "secondary",
            "steps": SLIDE15_STEPS,
        },
    ],
}


# ════════════════════════════════════════════════════════════════
#  GENERATE HTML
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    html_output = generate_html(config)
    out_path = Path(__file__).parent / "deep-dive.html"
    out_path.write_text(html_output, encoding="utf-8")
    print(f"Generated: {out_path} ({len(html_output):,} bytes)")
    print(f"  Slides: {len(config['slides'])}")
    print(f"  Gaps documented: {len(SLIDE15_STEPS)}")
