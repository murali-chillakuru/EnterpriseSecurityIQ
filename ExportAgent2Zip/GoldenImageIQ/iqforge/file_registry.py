"""Tracks which files are copy, parameterized, or generated."""

from __future__ import annotations

# ── Copy-tier files (domain-agnostic, copied verbatim) ─────────────

COPY_FILES: dict[str, str] = {
    # source (relative to templates/copy/) → destination (relative to output)
    "blob_store.py":                "AIAgent/app/blob_store.py",
    "evidence_history.py":          "AIAgent/app/evidence_history.py",
    "logger.py":                    "AIAgent/app/logger.py",
    "collectors/registry.py":       "AIAgent/app/collectors/__init__.py",
    "collectors/base.py":           "AIAgent/app/collectors/base.py",
    "core/models.py":               "AIAgent/app/core/models.py",
    "reports/shared_theme.py":      "AIAgent/app/reports/shared_theme.py",
    "reports/pdf_export.py":        "AIAgent/app/reports/pdf_export.py",
    "reports/excel_export.py":      "AIAgent/app/reports/excel_export.py",
    "reports/sarif_export.py":      "AIAgent/app/reports/sarif_export.py",
    "reports/data_exports.py":      "AIAgent/app/reports/data_exports.py",
    "Dockerfile":                   "AIAgent/Dockerfile",
}

# ── Parameterized templates (Jinja2 .j2 files) ─────────────────────

PARAMETERIZED_FILES: dict[str, str] = {
    # source (relative to templates/parameterized/) → destination
    "main.py.j2":                   "AIAgent/main.py",
    "api.py.j2":                    "AIAgent/app/api.py",
    "agent.py.j2":                  "AIAgent/app/agent.py",
    "orchestrator.py.j2":           "AIAgent/app/{_project_snake}_orchestrator.py",
    "engine.py.j2":                 "AIAgent/app/{_project_snake}_evaluators/engine.py",
    "config.py.j2":                 "AIAgent/app/core/config.py",
    "config.json.j2":               "config/{_project_snake}.config.json",
    "config.schema.json.j2":        "config/config.schema.json",
    "requirements.txt.j2":          "AIAgent/requirements.txt",
    "deploy.ps1.j2":                "Infra/deploy.ps1",
    "manifest.json.j2":             "teams/appPackage/manifest.json",
    "index.html.j2":                "webapp/index.html",
    "gitignore.j2":                 ".gitignore",
    "readme.md.j2":                 "README.md",
}

# ── Generated files (one per data-source / domain / framework) ─────

STUB_TEMPLATES: dict[str, str] = {
    # template → destination pattern (uses {source}, {name}, {framework_id}, {domain})
    "collector.py.j2":              "AIAgent/app/collectors/{source}/{name}.py",
    "evaluator.py.j2":              "AIAgent/app/{_project_snake}_evaluators/{domain}.py",
    "framework-mapping.json.j2":    "AIAgent/app/{_project_snake}_frameworks/{framework_id}-mappings.json",
    "assessment-page.html.j2":      "webapp/{page_name}.html",
}

# ── Empty __init__.py files to create ───────────────────────────────

INIT_PACKAGES: list[str] = [
    "AIAgent/app/__init__.py",
    "AIAgent/app/core/__init__.py",
    "AIAgent/app/collectors/__init__.py",
    "AIAgent/app/collectors/azure/__init__.py",
    "AIAgent/app/collectors/graph/__init__.py",
    "AIAgent/app/collectors/custom/__init__.py",
    "AIAgent/app/reports/__init__.py",
    "AIAgent/app/{_project_snake}_evaluators/__init__.py",
    "AIAgent/app/{_project_snake}_frameworks/.gitkeep",
]

# ── Directories to ensure exist ─────────────────────────────────────

DIRS: list[str] = [
    "AIAgent/app",
    "AIAgent/app/core",
    "AIAgent/app/collectors/azure",
    "AIAgent/app/collectors/graph",
    "AIAgent/app/collectors/custom",
    "AIAgent/app/reports",
    "AIAgent/output",
    "AIAgent/tests",
    "config",
    "schemas",
    "webapp",
    "Infra",
    "teams/appPackage",
    "docs",
    "examples",
    "output",
]
