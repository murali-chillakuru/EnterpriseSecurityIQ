"""SARIF 2.1.0 export — Static Analysis Results Interchange Format."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def export_sarif(
    findings: list[dict[str, Any]],
    tool_name: str,
    tool_version: str = "1.0.0",
    output_path: str | Path = "results.sarif",
) -> Path:
    """Write findings as SARIF 2.1.0."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }

    rules = []
    results = []
    rule_ids_seen: set[str] = set()

    for f in findings:
        ctrl_id = f.get("ControlId", "unknown")
        if ctrl_id not in rule_ids_seen:
            rule_ids_seen.add(ctrl_id)
            rules.append({
                "id": ctrl_id,
                "shortDescription": {"text": f.get("ControlTitle", ctrl_id)},
                "defaultConfiguration": {
                    "level": severity_map.get(f.get("Severity", "").lower(), "note")
                },
            })

        results.append({
            "ruleId": ctrl_id,
            "level": severity_map.get(f.get("Severity", "").lower(), "note"),
            "message": {"text": f.get("Description", "No description")},
            "properties": {
                "findingId": f.get("FindingId"),
                "status": f.get("Status"),
                "domain": f.get("Domain"),
                "framework": f.get("Framework"),
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    log.info("SARIF exported: %s (%d results)", output_path, len(results))
    return output_path
