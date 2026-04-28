"""Raw data exports — save evidence and findings as individual JSON files.

Returns a list of file paths (not a directory path) so that the ZIP bundler
can pick up each file individually.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def save_raw_evidence(
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    run_dir: Path,
) -> list[str]:
    """Save raw evidence + findings JSON. Returns list of individual file paths."""
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []

    # Evidence
    ev_path = raw_dir / "evidence.json"
    ev_path.write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")
    written.append(str(ev_path))

    # Findings
    find_path = raw_dir / "findings.json"
    find_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    written.append(str(find_path))

    log.info("Raw evidence written: %d files", len(written))
    return written
