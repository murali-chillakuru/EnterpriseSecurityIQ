"""Validate domain-definition YAML against the expected schema."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    print("ERROR: PyYAML is required.  pip install pyyaml")
    sys.exit(1)


# ── Required top-level keys ──────────────────────────────────────────

_REQUIRED_TOP = {"project_name", "description", "base_name", "data_sources", "frameworks"}
_OPTIONAL_TOP = {"reports", "azure", "spa_pages", "teams", "thresholds", "additional_tools"}

_REQUIRED_FRAMEWORK = {"id", "name", "version", "domains", "controls"}
_REQUIRED_CONTROL = {"id", "title", "domain", "severity", "evaluation_logic", "evidence_types"}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_SOURCES = {"azure", "graph", "custom"}


def load_and_validate(path: Path) -> dict[str, Any] | None:
    """Load YAML and validate structure. Returns config dict or None on error."""
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        return None

    with open(path, "r", encoding="utf-8") as f:
        try:
            cfg = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f"ERROR: Invalid YAML: {exc}")
            return None

    if not isinstance(cfg, dict):
        print("ERROR: YAML root must be a mapping")
        return None

    errors: list[str] = []

    # Top-level keys
    missing = _REQUIRED_TOP - cfg.keys()
    if missing:
        errors.append(f"Missing required keys: {sorted(missing)}")

    unknown = cfg.keys() - _REQUIRED_TOP - _OPTIONAL_TOP
    if unknown:
        errors.append(f"Unknown top-level keys: {sorted(unknown)}")

    # project_name / base_name
    for key in ("project_name", "base_name"):
        val = cfg.get(key, "")
        if not isinstance(val, str) or not val.strip():
            errors.append(f"'{key}' must be a non-empty string")

    # data_sources
    ds = cfg.get("data_sources", {})
    if not isinstance(ds, dict):
        errors.append("'data_sources' must be a mapping (azure/graph/custom)")
    else:
        for source, collectors in ds.items():
            if source not in _VALID_SOURCES:
                errors.append(f"Unknown data source type: '{source}' (valid: {sorted(_VALID_SOURCES)})")
            if not isinstance(collectors, list) or not collectors:
                errors.append(f"data_sources.{source} must be a non-empty list")
                continue
            for i, coll in enumerate(collectors):
                if not isinstance(coll, dict):
                    errors.append(f"data_sources.{source}[{i}] must be a mapping")
                    continue
                if "name" not in coll:
                    errors.append(f"data_sources.{source}[{i}] missing 'name'")
                if "evidence_types" not in coll or not coll["evidence_types"]:
                    errors.append(f"data_sources.{source}[{i}] missing 'evidence_types'")

    # frameworks
    frameworks = cfg.get("frameworks", [])
    if not isinstance(frameworks, list) or not frameworks:
        errors.append("'frameworks' must be a non-empty list")
    else:
        all_domains: set[str] = set()
        for i, fw in enumerate(frameworks):
            if not isinstance(fw, dict):
                errors.append(f"frameworks[{i}] must be a mapping")
                continue
            fw_missing = _REQUIRED_FRAMEWORK - fw.keys()
            if fw_missing:
                errors.append(f"frameworks[{i}] ({fw.get('id', '?')}) missing: {sorted(fw_missing)}")
            domains = fw.get("domains", [])
            if not isinstance(domains, list) or not domains:
                errors.append(f"frameworks[{i}] 'domains' must be a non-empty list")
            else:
                all_domains.update(domains)
            controls = fw.get("controls", [])
            if not isinstance(controls, list):
                errors.append(f"frameworks[{i}] 'controls' must be a list")
                continue
            for j, ctrl in enumerate(controls):
                if not isinstance(ctrl, dict):
                    errors.append(f"frameworks[{i}].controls[{j}] must be a mapping")
                    continue
                ctrl_missing = _REQUIRED_CONTROL - ctrl.keys()
                if ctrl_missing:
                    errors.append(f"frameworks[{i}].controls[{j}] ({ctrl.get('id', '?')}) missing: {sorted(ctrl_missing)}")
                sev = ctrl.get("severity", "")
                if sev and sev not in _VALID_SEVERITIES:
                    errors.append(f"frameworks[{i}].controls[{j}] invalid severity: '{sev}'")
                dom = ctrl.get("domain", "")
                if dom and domains and dom not in domains:
                    errors.append(f"frameworks[{i}].controls[{j}] domain '{dom}' not in framework domains {domains}")

    # reports
    reports = cfg.get("reports", ["html", "pdf", "xlsx"])
    valid_reports = {"html", "pdf", "xlsx", "sarif", "oscal", "csv", "markdown"}
    if not isinstance(reports, list):
        errors.append("'reports' must be a list")
    else:
        for r in reports:
            if r not in valid_reports:
                errors.append(f"Unknown report format: '{r}' (valid: {sorted(valid_reports)})")

    if errors:
        print(f"ERROR: {len(errors)} validation error(s) in {path.name}:")
        for e in errors:
            print(f"  - {e}")
        return None

    # Inject defaults
    cfg.setdefault("reports", ["html", "pdf", "xlsx"])
    cfg.setdefault("azure", {})
    cfg["azure"].setdefault("location", "swedencentral")
    cfg["azure"].setdefault("container_apps_location", "northeurope")
    cfg["azure"].setdefault("models", {"primary": "gpt-4.1", "fallback": "gpt-5.1"})
    cfg.setdefault("spa_pages", [])
    cfg.setdefault("thresholds", {})
    cfg.setdefault("additional_tools", [])

    # Computed fields
    cfg["_all_domains"] = sorted({d for fw in cfg["frameworks"] for d in fw.get("domains", [])})
    cfg["_all_evidence_types"] = sorted({
        et
        for src in cfg["data_sources"].values()
        for coll in src
        for et in coll.get("evidence_types", [])
    })
    cfg["_project_lower"] = cfg["project_name"].lower().replace(" ", "").replace("-", "")
    cfg["_project_snake"] = cfg["project_name"].lower().replace(" ", "_").replace("-", "_")

    print(f"  Validated: {cfg['project_name']}")
    return cfg
