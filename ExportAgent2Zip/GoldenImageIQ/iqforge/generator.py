"""Core scaffolding engine — reads config, renders templates, writes output."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined  # type: ignore
except ImportError:
    raise SystemExit("ERROR: Jinja2 is required.  pip install jinja2")

from iqforge.file_registry import (
    COPY_FILES,
    DIRS,
    INIT_PACKAGES,
    PARAMETERIZED_FILES,
    STUB_TEMPLATES,
)

_TEMPLATE_ROOT = Path(__file__).resolve().parent.parent / "templates"


def _resolve_path(pattern: str, cfg: dict[str, Any], **extra: str) -> str:
    """Substitute {placeholders} in a path pattern."""
    merged = {**cfg, **extra}
    result = pattern
    for key, val in merged.items():
        result = result.replace(f"{{{key}}}", str(val))
    return result


def _jinja_env(template_dir: Path) -> Environment:
    """Create a Jinja2 environment rooted at template_dir."""
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_project(cfg: dict[str, Any], output_dir: Path) -> None:
    """Generate a complete IQ-platform repo at output_dir."""
    print(f"\n  Generating {cfg['project_name']} at {output_dir}\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    stats = {"copied": 0, "rendered": 0, "generated": 0, "dirs": 0}

    # ── 1. Create directory structure ──────────────────────────────
    for d in DIRS:
        resolved = _resolve_path(d, cfg)
        (output_dir / resolved).mkdir(parents=True, exist_ok=True)
        stats["dirs"] += 1

    # Create evaluator + framework dirs
    eval_dir = output_dir / f"AIAgent/app/{cfg['_project_snake']}_evaluators"
    fw_dir = output_dir / f"AIAgent/app/{cfg['_project_snake']}_frameworks"
    eval_dir.mkdir(parents=True, exist_ok=True)
    fw_dir.mkdir(parents=True, exist_ok=True)

    # ── 2. Create __init__.py files ────────────────────────────────
    for pkg in INIT_PACKAGES:
        resolved = _resolve_path(pkg, cfg)
        p = output_dir / resolved
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("", encoding="utf-8")

    # ── 3. Copy-tier files ─────────────────────────────────────────
    copy_dir = _TEMPLATE_ROOT / "copy"
    for src_rel, dst_rel in COPY_FILES.items():
        src = copy_dir / src_rel
        dst = output_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.copy2(src, dst)
            stats["copied"] += 1
            print(f"    [copy]  {dst_rel}")
        else:
            print(f"    [SKIP]  {src_rel} (template not found)")

    # ── 4. Parameterized templates ─────────────────────────────────
    param_dir = _TEMPLATE_ROOT / "parameterized"
    env = _jinja_env(param_dir)
    for src_rel, dst_pattern in PARAMETERIZED_FILES.items():
        dst_rel = _resolve_path(dst_pattern, cfg)
        dst = output_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmpl = env.get_template(src_rel)
            content = tmpl.render(**cfg)
            dst.write_text(content, encoding="utf-8")
            stats["rendered"] += 1
            print(f"    [tmpl]  {dst_rel}")
        except Exception as exc:
            print(f"    [ERR]   {src_rel} → {exc}")

    # ── 5. Generated files (stubs) ─────────────────────────────────
    stub_dir = _TEMPLATE_ROOT / "stubs"
    stub_env = _jinja_env(stub_dir)

    # 5a. Collector stubs
    for source, collectors in cfg.get("data_sources", {}).items():
        for coll in collectors:
            name = coll["name"]
            dst_rel = _resolve_path(
                STUB_TEMPLATES["collector.py.j2"],
                cfg, source=source, name=name,
            )
            dst = output_dir / dst_rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                tmpl = stub_env.get_template("collector.py.j2")
                content = tmpl.render(collector=coll, source=source, **cfg)
                dst.write_text(content, encoding="utf-8")
                stats["generated"] += 1
                print(f"    [stub]  {dst_rel}")
            except Exception as exc:
                print(f"    [ERR]   collector {name}: {exc}")

    # 5b. Evaluator stubs
    for domain in cfg["_all_domains"]:
        dst_rel = _resolve_path(
            STUB_TEMPLATES["evaluator.py.j2"],
            cfg, domain=domain,
        )
        dst = output_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Gather all check functions for this domain across frameworks
        checks = []
        for fw in cfg["frameworks"]:
            for ctrl in fw.get("controls", []):
                if ctrl.get("domain") == domain:
                    checks.append({
                        "control_id": ctrl["id"],
                        "evaluation_logic": ctrl["evaluation_logic"],
                        "title": ctrl.get("title", ""),
                        "severity": ctrl.get("severity", "medium"),
                    })
        try:
            tmpl = stub_env.get_template("evaluator.py.j2")
            content = tmpl.render(domain=domain, checks=checks, **cfg)
            dst.write_text(content, encoding="utf-8")
            stats["generated"] += 1
            print(f"    [stub]  {dst_rel}")
        except Exception as exc:
            print(f"    [ERR]   evaluator {domain}: {exc}")

    # 5c. Framework mapping JSONs
    for fw in cfg["frameworks"]:
        fw_id = fw["id"].lower().replace(" ", "-")
        dst_rel = _resolve_path(
            STUB_TEMPLATES["framework-mapping.json.j2"],
            cfg, framework_id=fw_id,
        )
        dst = output_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmpl = stub_env.get_template("framework-mapping.json.j2")
            content = tmpl.render(framework=fw, **cfg)
            dst.write_text(content, encoding="utf-8")
            stats["generated"] += 1
            print(f"    [stub]  {dst_rel}")
        except Exception as exc:
            print(f"    [ERR]   framework {fw_id}: {exc}")

    # 5d. SPA assessment pages
    _default_pages = [{"name": cfg["project_name"], "title": cfg["project_name"] + " Assessment"}]
    pages = cfg.get("spa_pages") or _default_pages
    for page in pages:
        page_name = page["name"].replace(" ", "")
        dst_rel = _resolve_path(
            STUB_TEMPLATES["assessment-page.html.j2"],
            cfg, page_name=page_name,
        )
        dst = output_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmpl = stub_env.get_template("assessment-page.html.j2")
            content = tmpl.render(page=page, **cfg)
            dst.write_text(content, encoding="utf-8")
            stats["generated"] += 1
            print(f"    [stub]  {dst_rel}")
        except Exception as exc:
            print(f"    [ERR]   page {page_name}: {exc}")

    # ── 6. JSON Schemas ────────────────────────────────────────────
    _write_schemas(output_dir, cfg)

    # ── Summary ────────────────────────────────────────────────────
    print(f"\n  Done! {cfg['project_name']} scaffolded at {output_dir}")
    print(f"  {stats['dirs']} dirs | {stats['copied']} copied | "
          f"{stats['rendered']} rendered | {stats['generated']} generated")
    print(f"\n  Next steps:")
    print(f"    1. Fill in collector API logic  in AIAgent/app/collectors/")
    print(f"    2. Fill in check_* functions    in AIAgent/app/{cfg['_project_snake']}_evaluators/")
    print(f"    3. Run: cd Infra && .\\deploy.ps1")
    print()


def _write_schemas(output_dir: Path, cfg: dict[str, Any]) -> None:
    """Write JSON Schema files for evidence + finding records."""
    schemas_dir = output_dir / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)

    evidence_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{cfg['project_name']} Evidence Record",
        "type": "object",
        "required": ["EvidenceId", "EvidenceType", "Source", "Collector", "CollectedAt"],
        "properties": {
            "EvidenceId": {"type": "string", "format": "uuid"},
            "EvidenceType": {"type": "string"},
            "Source": {"type": "string", "enum": ["azure", "graph", "custom"]},
            "Collector": {"type": "string"},
            "Description": {"type": "string"},
            "CollectedAt": {"type": "string", "format": "date-time"},
            "ResourceId": {"type": "string"},
            "ResourceType": {"type": "string"},
            "Data": {"type": "object"},
        },
    }

    finding_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{cfg['project_name']} Finding Record",
        "type": "object",
        "required": ["FindingId", "ControlId", "Framework", "Status", "Severity"],
        "properties": {
            "FindingId": {"type": "string", "format": "uuid"},
            "ControlId": {"type": "string"},
            "Framework": {"type": "string"},
            "ControlTitle": {"type": "string"},
            "Status": {"type": "string", "enum": [
                "compliant", "non_compliant", "not_assessed",
                "missing_evidence", "partial", "unable_to_assess",
            ]},
            "Severity": {"type": "string", "enum": [
                "critical", "high", "medium", "low", "informational",
            ]},
            "Domain": {"type": "string"},
            "Description": {"type": "string"},
            "Recommendation": {"type": "string"},
            "ResourceId": {"type": "string"},
            "ResourceType": {"type": "string"},
            "SupportingEvidence": {"type": "array", "items": {"type": "object"}},
            "EvaluatedAt": {"type": "string", "format": "date-time"},
        },
    }

    (schemas_dir / "evidence-record.schema.json").write_text(
        json.dumps(evidence_schema, indent=2), encoding="utf-8"
    )
    (schemas_dir / "finding-record.schema.json").write_text(
        json.dumps(finding_schema, indent=2), encoding="utf-8"
    )
