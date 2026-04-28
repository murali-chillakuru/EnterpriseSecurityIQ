"""
Tool → modules dependency map.

Used by package_agent.py to compute which AIAgent/app/ subtrees and webapp/ pages
must be included in a staged copy for a given tool selection.

To add a new tool when the source repo grows:
  1. Add a key under TOOL_MODULES naming the tool function (must match the name
     in api.py TOOL_SCHEMAS).
  2. Provide the list of paths (relative to repo root) that must be copied.
  3. Optionally add a webapp page mapping under TOOL_PAGES.
"""

# Always-on backend modules (required by api.py + agent.py regardless of tool selection).
# Backend is shipped FULL by default (Option B). These are the bare minimum.
ALWAYS_ON_BACKEND = [
    "AIAgent/app/__init__.py",
    "AIAgent/app/api.py",
    "AIAgent/app/agent.py",
    "AIAgent/app/auth.py",
    "AIAgent/app/config.py",
    "AIAgent/app/models.py",
    "AIAgent/app/logger.py",
    "AIAgent/app/i18n.py",
    "AIAgent/app/locales/",
    "AIAgent/app/blob_store.py",
    "AIAgent/app/evidence_history.py",
    "AIAgent/app/continuous_monitor.py",
    "AIAgent/app/operational_integrations.py",
    "AIAgent/app/siem_integration.py",
    "AIAgent/app/remediation_engine.py",
    "AIAgent/app/query_engine.py",
    "AIAgent/app/cloud_explorer/",
    "AIAgent/app/collectors/",
    "AIAgent/app/core/",
    "AIAgent/app/reports/",
    "AIAgent/app/tools/",
    "AIAgent/app/query_evaluators/",
    "AIAgent/app/query_frameworks/",
    "AIAgent/main.py",
    "AIAgent/requirements.txt",
    "AIAgent/Dockerfile",
    "AIAgent/agent.yaml",
    "AIAgent/README.md",
]

# Per-tool extra modules (added on top of ALWAYS_ON_BACKEND when the tool is selected).
TOOL_MODULES = {
    "run_postureiq_assessment": [
        "AIAgent/app/postureiq_orchestrator.py",
        "AIAgent/app/postureiq_evaluators/",
        "AIAgent/app/postureiq_frameworks/",
        "AIAgent/app/postureiq_reports/",
    ],
    "generate_rbac_report": [
        "AIAgent/app/rbac_orchestrator.py",
        "AIAgent/app/rbac_evaluators/",
        "AIAgent/app/rbac_frameworks/",
        "AIAgent/app/rbac_reports/",
    ],
    "analyze_risk": [
        "AIAgent/app/risk_engine.py",
        "AIAgent/app/risk_orchestrator.py",
        "AIAgent/app/risk_evaluators/",
        "AIAgent/app/risk_frameworks/",
        "AIAgent/app/risk_reports/",
    ],
    "search_exposure": [],   # uses query_engine + cloud_explorer (already always-on)
    "generate_custom_report": [],  # uses reports/ (already always-on)
    "assess_data_security": [
        "AIAgent/app/data_security_engine.py",
        "AIAgent/app/data_residency_engine.py",
        "AIAgent/app/datasec_evaluators/",
        "AIAgent/app/datasec_frameworks/",
        "AIAgent/app/datasec_orchestrator.py",
        "AIAgent/app/datasec_reports/",
    ],
    "assess_copilot_readiness": [
        "AIAgent/app/copilot_readiness_engine.py",
        "AIAgent/app/copilot_evaluators/",
        "AIAgent/app/copilot_frameworks/",
        "AIAgent/app/copilot_orchestrator.py",
        "AIAgent/app/copilot_reports/",
    ],
    "assess_ai_agent_security": [
        "AIAgent/app/ai_agent_security_engine.py",
        "AIAgent/app/aiagentsec_evaluators/",
        "AIAgent/app/aiagentsec_frameworks/",
        "AIAgent/app/aiagentsec_orchestrator.py",
        "AIAgent/app/aiagentsec_reports/",
    ],
    "run_attack_path_detection": [
        "AIAgent/app/attack_path_engine.py",
        "AIAgent/app/attackpath_evaluators/",
        "AIAgent/app/attackpath_frameworks/",
        "AIAgent/app/attackpath_orchestrator.py",
        "AIAgent/app/attackpath_reports/",
    ],
    # Always-on tools (no extra modules)
    "query_results": [],
    "search_tenant": [],
    "check_permissions": [],
    "compare_runs": [],
    "generate_report": [],
    "query_assessment_history": [],
}

# Webapp pages always shared
ALWAYS_ON_WEBAPP = [
    "webapp/auth-end.html",
    "webapp/auth-start.html",
    "webapp/msal-browser.min.js",
    "webapp/teams-init.js",
    "webapp/generate_pages.py",
    "webapp/_verify.py",
    "webapp/README.md",
]

# Always-on root scaffolding
ALWAYS_ON_ROOT = [
    "Infra-Foundary-New/",
    "config/",
    "examples/",
    "schemas/",
    "CHANGELOG.md",
]

# Excluded everywhere
EXCLUDE_PATTERNS = [
    ".venv", "__pycache__", ".git", ".github",
    "output", "docs", "Technical-Docs", "POC-Foundry-New",
    "Murali-Analysis", "node_modules", ".pytest_cache",
    ".vscode", ".idea", "*.pyc", "*.pyo",
]
