"""Evidence history — track and compare assessment runs over time."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def save_snapshot(evidence: list[dict], findings: list[dict], run_dir: Path) -> Path:
    """Save a snapshot of current evidence + findings for delta comparisons."""
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_count": len(evidence),
        "finding_count": len(findings),
        "findings_summary": _summarise_findings(findings),
    }
    snap_path = run_dir / "snapshot.json"
    snap_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    return snap_path


def load_previous_snapshot(output_base: Path) -> dict | None:
    """Load the most recent previous snapshot for delta comparison."""
    candidates = sorted(output_base.glob("*/snapshot.json"), reverse=True)
    if len(candidates) < 2:
        return None
    # First is current run, second is previous
    prev = candidates[1]
    try:
        return json.loads(prev.read_text(encoding="utf-8"))
    except Exception:
        log.warning("Could not load previous snapshot: %s", prev)
        return None


def compute_delta(current: dict, previous: dict | None) -> dict:
    """Compute drift between current and previous snapshot."""
    if previous is None:
        return {"status": "first_run", "changes": []}

    changes = []
    for key in ("evidence_count", "finding_count"):
        cur = current.get(key, 0)
        prev = previous.get(key, 0)
        if cur != prev:
            changes.append({"field": key, "previous": prev, "current": cur, "delta": cur - prev})

    cur_summary = current.get("findings_summary", {})
    prev_summary = previous.get("findings_summary", {})
    for sev in ("critical", "high", "medium", "low"):
        c = cur_summary.get(sev, 0)
        p = prev_summary.get(sev, 0)
        if c != p:
            changes.append({"field": f"severity_{sev}", "previous": p, "current": c, "delta": c - p})

    return {"status": "delta", "changes": changes}


def _summarise_findings(findings: list[dict]) -> dict:
    """Count findings by severity."""
    summary: dict[str, int] = {}
    for f in findings:
        sev = f.get("Severity", "informational").lower()
        summary[sev] = summary.get(sev, 0) + 1
    return summary
