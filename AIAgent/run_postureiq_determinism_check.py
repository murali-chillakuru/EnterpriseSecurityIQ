#!/usr/bin/env python
"""
Live determinism validation for PostureIQ Compliance Assessment.

Collects evidence from the real tenant once, then re-runs the
evaluation pipeline (evaluate_all) 3 times from the same captured
evidence and compares all outputs for consistency.

Usage:
  python run_postureiq_determinism_check.py --tenant <tenant-id>
  python run_postureiq_determinism_check.py --tenant <tenant-id> --evidence output/<ts>/raw-evidence.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

from app.auth import ComplianceCredentials
from app.postureiq_evaluators.engine import evaluate_all
from app.logger import log


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _run_evaluation(evidence: list[dict], run_label: str) -> dict:
    """Run evaluate_all on evidence and return results."""
    print(f"\n  Running evaluation ({run_label}) …")
    results = evaluate_all(evidence)

    findings = results.get("findings", [])
    controls = results.get("control_results", [])
    summary = results.get("summary", {})

    print(f"    Findings: {len(findings)} | Controls: {len(controls)}")
    print(f"    Overall Score: {summary.get('OverallScore', 'N/A')}")

    return {
        "RunLabel": run_label,
        "FindingCount": len(findings),
        "ControlCount": len(controls),
        "Findings": findings,
        "ControlResults": controls,
        "Summary": summary,
        "FrameworkSummaries": results.get("framework_summaries", {}),
    }


def _strip_volatile(obj):
    """Recursively strip timestamp and volatile fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k not in ("EvaluatedAt", "RunLabel")
        }
    if isinstance(obj, list):
        return [_strip_volatile(item) for item in obj]
    return obj


def _compare_runs(runs: list[dict]) -> dict:
    """Compare 3 runs and produce a detailed comparison report."""
    report: dict = {
        "ComparedAt": datetime.now(timezone.utc).isoformat(),
        "RunCount": len(runs),
        "Runs": [],
        "FindingIdComparison": {},
        "FieldLevelDiffs": [],
        "ScoreComparison": {},
        "ControlComparison": {},
        "Verdict": "UNKNOWN",
    }

    # ── Run summaries ────────────────────────────────────────────
    for r in runs:
        summary = r.get("Summary", {})
        report["Runs"].append({
            "Label": r["RunLabel"],
            "FindingCount": r["FindingCount"],
            "ControlCount": r["ControlCount"],
            "OverallScore": summary.get("OverallScore"),
        })

    # ── Finding ID comparison ────────────────────────────────────
    id_field = "FindingId"
    id_sets = []
    for r in runs:
        ids = set()
        for f in r["Findings"]:
            fid = f.get(id_field) or f.get("finding_id", "")
            if fid:
                ids.add(fid)
        id_sets.append(ids)

    all_ids_match = id_sets[0] == id_sets[1] == id_sets[2]
    report["FindingIdComparison"] = {
        "AllIdentical": all_ids_match,
        "Run1Count": len(id_sets[0]),
        "Run2Count": len(id_sets[1]),
        "Run3Count": len(id_sets[2]),
        "OnlyInRun1": sorted(id_sets[0] - id_sets[1] - id_sets[2]),
        "OnlyInRun2": sorted(id_sets[1] - id_sets[0] - id_sets[2]),
        "OnlyInRun3": sorted(id_sets[2] - id_sets[0] - id_sets[1]),
    }

    # ── Field-level diff on common findings ──────────────────────
    common_ids = id_sets[0] & id_sets[1] & id_sets[2]
    findings_by_id = []
    for r in runs:
        idx = {}
        for f in r["Findings"]:
            fid = f.get(id_field) or f.get("finding_id", "")
            if fid:
                idx[fid] = f
        findings_by_id.append(idx)

    skip_keys = {"EvaluatedAt", "RunLabel"}
    diff_count = 0
    for fid in sorted(common_ids):
        f1, f2, f3 = findings_by_id[0][fid], findings_by_id[1][fid], findings_by_id[2][fid]
        all_keys = sorted(set(f1.keys()) | set(f2.keys()) | set(f3.keys()))
        for k in all_keys:
            if k in skip_keys:
                continue
            v1, v2, v3 = f1.get(k), f2.get(k), f3.get(k)
            if v1 != v2 or v1 != v3:
                diff_count += 1
                report["FieldLevelDiffs"].append({
                    "FindingId": fid,
                    "Field": k,
                    "Run1": str(v1)[:200],
                    "Run2": str(v2)[:200],
                    "Run3": str(v3)[:200],
                })

    # ── Score comparison ─────────────────────────────────────────
    summaries = [r.get("Summary", {}) for r in runs]
    overall_scores = [s.get("OverallScore") for s in summaries]
    report["ScoreComparison"] = {
        "OverallScoresIdentical": len(set(str(s) for s in overall_scores)) == 1,
        "OverallScores": overall_scores,
    }

    # ── Control comparison ───────────────────────────────────────
    ctrl_jsons = [
        json.dumps(_strip_volatile(r["ControlResults"]), sort_keys=True, default=str)
        for r in runs
    ]
    ctrl_match = ctrl_jsons[0] == ctrl_jsons[1] == ctrl_jsons[2]
    report["ControlComparison"] = {
        "AllIdentical": ctrl_match,
        "Counts": [r["ControlCount"] for r in runs],
    }

    # ── Full JSON comparison (excluding volatile fields) ─────────
    clean_runs = [_strip_volatile(r) for r in runs]
    json_a = json.dumps(clean_runs[0], sort_keys=True, default=str)
    json_b = json.dumps(clean_runs[1], sort_keys=True, default=str)
    json_c = json.dumps(clean_runs[2], sort_keys=True, default=str)
    full_json_match = (json_a == json_b == json_c)

    # ── Verdict ──────────────────────────────────────────────────
    all_pass = (
        all_ids_match
        and diff_count == 0
        and full_json_match
        and ctrl_match
        and len(set(str(s) for s in overall_scores)) == 1
    )
    report["Verdict"] = "PASS ✓ — All 3 runs are deterministic" if all_pass else "FAIL ✗ — Differences detected"
    report["FullJsonMatch"] = full_json_match
    report["FieldLevelDiffCount"] = diff_count

    return report


def _print_comparison(report: dict) -> None:
    """Print comparison results to console."""
    _print_header("DETERMINISM COMPARISON RESULTS")

    print("\n  Run Summaries:")
    for r in report["Runs"]:
        print(f"    {r['Label']}: {r['FindingCount']} findings | "
              f"{r['ControlCount']} controls | Score={r['OverallScore']}")

    fic = report["FindingIdComparison"]
    print(f"\n  Finding IDs: {'✓ All identical' if fic['AllIdentical'] else '✗ DIFFER'}")
    if not fic["AllIdentical"]:
        for key in ("OnlyInRun1", "OnlyInRun2", "OnlyInRun3"):
            ids = fic[key]
            if ids:
                print(f"    {key}: {ids[:5]}")

    print(f"\n  Field-level diffs: {report['FieldLevelDiffCount']}")
    for d in report.get("FieldLevelDiffs", [])[:10]:
        print(f"    {d['FindingId']}.{d['Field']}:")
        print(f"      Run1: {d['Run1'][:100]}")
        print(f"      Run2: {d['Run2'][:100]}")
        print(f"      Run3: {d['Run3'][:100]}")

    sc = report["ScoreComparison"]
    print(f"\n  Scores: {'✓ All identical' if sc['OverallScoresIdentical'] else '✗ DIFFER'} ({sc['OverallScores']})")

    cc = report["ControlComparison"]
    print(f"  Controls: {'✓ All identical' if cc['AllIdentical'] else '✗ DIFFER'} (counts: {cc['Counts']})")
    print(f"  Full JSON Match: {'✓' if report['FullJsonMatch'] else '✗'}")

    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("PostureIQ — Compliance Assessment Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_postureiq_{ts}"
    os.makedirs(base_dir, exist_ok=True)

    creds = ComplianceCredentials(tenant_id=args.tenant)
    print(f"\n  Tenant: {args.tenant}")

    # ── Step 1: Get evidence ─────────────────────────────────────
    all_evidence: list[dict] = []

    if args.evidence:
        print(f"  Loading evidence from: {args.evidence}")
        with open(args.evidence, "r", encoding="utf-8") as fh:
            all_evidence = json.load(fh)
        print(f"  Loaded {len(all_evidence)} evidence records")
    else:
        print("  Collecting evidence from tenant (one-time) …")
        from app.collectors.registry import discover_collectors, get_collector_functions
        discover_collectors()
        subscriptions = await creds.list_subscriptions()

        azure_fns = get_collector_functions(source="azure")
        entra_fns = get_collector_functions(source="entra")

        for label, fns in [("Azure", azure_fns), ("Entra", entra_fns)]:
            for fn in fns:
                try:
                    if label == "Azure":
                        result = await asyncio.wait_for(fn(creds, subscriptions), timeout=120)
                    else:
                        result = await asyncio.wait_for(fn(creds), timeout=120)
                    if isinstance(result, list):
                        all_evidence.extend(result)
                except Exception as e:
                    print(f"    WARN: {fn.__name__} — {e}")

        print(f"  Collected {len(all_evidence)} evidence records")

        # Save evidence for reuse
        evidence_path = base_dir / "raw-evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fh:
            json.dump(all_evidence, fh, indent=2, default=str)
        print(f"  Evidence saved: {evidence_path}")

    # ── Step 2: Run evaluation 3 times ───────────────────────────
    _print_header("RUNNING 3 EVALUATION PASSES")

    runs: list[dict] = []
    for i in range(1, 4):
        start = time.monotonic()
        result = _run_evaluation(all_evidence, f"Run {i}")
        elapsed = time.monotonic() - start
        runs.append(result)
        print(f"  Run {i}: {result['FindingCount']} findings, "
              f"score={result['Summary'].get('OverallScore', 'N/A')}, "
              f"{elapsed:.2f}s")

        # Save individual run
        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        with open(run_dir / "postureiq-assessment.json", "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)

    # ── Step 3: Compare ──────────────────────────────────────────
    _print_header("COMPARING RESULTS")
    report = _compare_runs(runs)

    report_path = base_dir / "determinism-comparison.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    _print_comparison(report)

    print(f"\n  Output directory: {base_dir}")
    print(f"  Comparison report: {report_path}")

    await creds.close()
    sys.exit(0 if "PASS" in report["Verdict"] else 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PostureIQ — Compliance Assessment Determinism Validation",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to raw-evidence.json from a prior run")
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
