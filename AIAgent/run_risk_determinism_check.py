#!/usr/bin/env python
"""
Live determinism validation for Risk Analysis.

Collects evidence from the real tenant once, then re-runs the
analysis pipeline 3 times from the same captured evidence and
compares all outputs for consistency.

NOTE: RiskFindingId uses uuid4() (random), so findings are matched
by (Category, Subcategory) composite key instead of by ID.

Usage:
  python run_risk_determinism_check.py --tenant <tenant-id>
  python run_risk_determinism_check.py --tenant <tenant-id> --evidence output/<ts>/risk-evidence.json
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
from app.risk_evaluators.identity import analyze_identity_risk
from app.risk_evaluators.network import analyze_network_risk
from app.risk_evaluators.config_drift import analyze_config_drift
from app.risk_evaluators.insider_risk import analyze_insider_risk
from app.risk_evaluators.scoring import compute_risk_scores
from app.risk_evaluators.enrichment import enrich_compliance_mapping
from app.logger import log


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_SYNC_ANALYZERS = [
    ("identity",   analyze_identity_risk),
    ("network",    analyze_network_risk),
    ("config",     analyze_config_drift),
    ("insider",    analyze_insider_risk),
]


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _finding_key(f: dict) -> str:
    """Stable composite key for matching findings across runs."""
    return f"{f.get('Category', '')}|{f.get('Subcategory', '')}"


def _run_analysis(evidence_index: dict[str, list[dict]], run_label: str, thresholds=None) -> dict:
    """Run the full sync analysis pipeline on evidence and return results."""
    print(f"\n  Running analysis ({run_label}) …")
    all_findings: list[dict] = []
    for name, fn in _SYNC_ANALYZERS:
        if name == "identity":
            findings = fn(evidence_index, thresholds)
        else:
            findings = fn(evidence_index)
        all_findings.extend(findings)
        print(f"    {name}: {len(findings)} findings")

    enrich_compliance_mapping(all_findings)

    # Deterministic sort (same as orchestrator)
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _SEVERITY_ORDER.get(f.get("Severity", "medium").lower(), 9),
        )
    )

    scores = compute_risk_scores(all_findings)

    return {
        "RunLabel": run_label,
        "FindingCount": len(all_findings),
        "Findings": all_findings,
        "RiskScores": scores,
    }


def _strip_volatile(obj):
    """Recursively strip timestamp and volatile fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k not in ("DetectedAt", "AnalyzedAt", "RunLabel",
                         "RiskFindingId", "AnalysisId")
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
        "FindingKeyComparison": {},
        "FieldLevelDiffs": [],
        "ScoreComparison": {},
        "Verdict": "UNKNOWN",
    }

    # ── Run summaries ────────────────────────────────────────────
    for r in runs:
        scores = r.get("RiskScores", {})
        report["Runs"].append({
            "Label": r["RunLabel"],
            "FindingCount": r["FindingCount"],
            "OverallRiskScore": scores.get("OverallRiskScore"),
            "RiskLevel": scores.get("RiskLevel"),
        })

    # ── Finding key comparison (by Category|Subcategory) ─────────
    key_sets = [
        set(_finding_key(f) for f in r["Findings"])
        for r in runs
    ]
    all_keys_match = key_sets[0] == key_sets[1] == key_sets[2]
    report["FindingKeyComparison"] = {
        "AllIdentical": all_keys_match,
        "Run1Count": len(key_sets[0]),
        "Run2Count": len(key_sets[1]),
        "Run3Count": len(key_sets[2]),
        "OnlyInRun1": sorted(key_sets[0] - key_sets[1] - key_sets[2]),
        "OnlyInRun2": sorted(key_sets[1] - key_sets[0] - key_sets[2]),
        "OnlyInRun3": sorted(key_sets[2] - key_sets[0] - key_sets[1]),
    }

    # ── Field-level diff on common findings ──────────────────────
    common_keys = key_sets[0] & key_sets[1] & key_sets[2]
    findings_by_key = []
    for r in runs:
        idx = {}
        for f in r["Findings"]:
            idx[_finding_key(f)] = f
        findings_by_key.append(idx)

    skip_fields = {"DetectedAt", "AnalyzedAt", "RunLabel", "RiskFindingId", "AnalysisId"}
    diff_count = 0
    for fk in sorted(common_keys):
        f1, f2, f3 = findings_by_key[0][fk], findings_by_key[1][fk], findings_by_key[2][fk]
        all_fields = sorted(set(f1.keys()) | set(f2.keys()) | set(f3.keys()))
        for k in all_fields:
            if k in skip_fields:
                continue
            v1, v2, v3 = f1.get(k), f2.get(k), f3.get(k)
            if v1 != v2 or v1 != v3:
                diff_count += 1
                report["FieldLevelDiffs"].append({
                    "FindingKey": fk,
                    "Field": k,
                    "Run1": str(v1)[:200],
                    "Run2": str(v2)[:200],
                    "Run3": str(v3)[:200],
                })

    # ── Score comparison ─────────────────────────────────────────
    scores = [r.get("RiskScores", {}) for r in runs]
    overall_scores = [s.get("OverallRiskScore") for s in scores]
    risk_levels = [s.get("RiskLevel") for s in scores]
    report["ScoreComparison"] = {
        "OverallScoresIdentical": len(set(str(s) for s in overall_scores)) == 1,
        "OverallScores": overall_scores,
        "RiskLevelsIdentical": len(set(str(s) for s in risk_levels)) == 1,
        "RiskLevels": risk_levels,
    }

    # ── Full JSON comparison (excluding volatile fields) ─────────
    clean_runs = [_strip_volatile(r) for r in runs]
    jsons = [json.dumps(c, sort_keys=True, default=str) for c in clean_runs]
    full_json_match = (jsons[0] == jsons[1] == jsons[2])

    # ── Verdict ──────────────────────────────────────────────────
    all_pass = (
        all_keys_match
        and diff_count == 0
        and full_json_match
        and len(set(str(s) for s in overall_scores)) == 1
    )
    report["Verdict"] = "PASS ✓ — All 3 runs are deterministic" if all_pass else "FAIL ✗ — Differences detected"
    report["FullJsonMatch"] = full_json_match
    report["FieldLevelDiffCount"] = diff_count

    return report


def _print_comparison(report: dict) -> None:
    _print_header("DETERMINISM COMPARISON RESULTS")

    print("\n  Run Summaries:")
    for r in report["Runs"]:
        print(f"    {r['Label']}: {r['FindingCount']} findings | "
              f"Score={r['OverallRiskScore']} | Level={r['RiskLevel']}")

    fkc = report["FindingKeyComparison"]
    print(f"\n  Finding Keys: {'✓ All identical' if fkc['AllIdentical'] else '✗ DIFFER'}")
    if not fkc["AllIdentical"]:
        for key in ("OnlyInRun1", "OnlyInRun2", "OnlyInRun3"):
            items = fkc[key]
            if items:
                print(f"    {key}: {items[:5]}")

    print(f"\n  Field-level diffs: {report['FieldLevelDiffCount']}")
    for d in report.get("FieldLevelDiffs", [])[:10]:
        print(f"    {d['FindingKey']}.{d['Field']}:")
        print(f"      Run1: {d['Run1'][:100]}")
        print(f"      Run2: {d['Run2'][:100]}")
        print(f"      Run3: {d['Run3'][:100]}")

    sc = report["ScoreComparison"]
    print(f"\n  Scores: {'✓ All identical' if sc['OverallScoresIdentical'] else '✗ DIFFER'} ({sc['OverallScores']})")
    print(f"  Risk Levels: {'✓ All identical' if sc['RiskLevelsIdentical'] else '✗ DIFFER'} ({sc['RiskLevels']})")
    print(f"  Full JSON Match: {'✓' if report['FullJsonMatch'] else '✗'}")

    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("PostureIQ — Risk Analysis Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_risk_{ts}"
    os.makedirs(base_dir, exist_ok=True)

    creds = ComplianceCredentials(tenant_id=args.tenant)
    print(f"\n  Tenant: {args.tenant}")

    # ── Step 1: Get evidence ─────────────────────────────────────
    evidence_index: dict[str, list[dict]] = {}

    if args.evidence:
        print(f"  Loading evidence from: {args.evidence}")
        with open(args.evidence, "r", encoding="utf-8") as fh:
            evidence_list = json.load(fh)
        for ev in evidence_list:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)
        print(f"  Loaded {sum(len(v) for v in evidence_index.values())} evidence records")
    else:
        print("  Collecting evidence from tenant (one-time) …")
        subscriptions = await creds.list_subscriptions()
        from app.risk_orchestrator import _lightweight_collect
        evidence_index = await _lightweight_collect(creds, subscriptions)
        rec_count = sum(len(v) for v in evidence_index.values())
        print(f"  Collected {rec_count} evidence records")

        # Save evidence for reuse
        evidence_flat: list[dict] = []
        for records in evidence_index.values():
            evidence_flat.extend(records)
        evidence_path = base_dir / "risk-evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fh:
            json.dump(evidence_flat, fh, indent=2, default=str)
        print(f"  Evidence saved: {evidence_path}")

    print(f"\n  Evidence types: {len(evidence_index)}")
    for etype, records in sorted(evidence_index.items()):
        print(f"    {etype}: {len(records)} records")

    # ── Step 2: Run analysis 3 times (sync analyzers only) ───────
    _print_header("RUNNING 3 ANALYSIS PASSES")
    print("  NOTE: analyze_defender_posture (async) is excluded — it depends")
    print("  on live creds. Only sync analyzers are tested for determinism.")

    runs: list[dict] = []
    for i in range(1, 4):
        start = time.monotonic()
        result = _run_analysis(evidence_index, f"Run {i}")
        elapsed = time.monotonic() - start
        runs.append(result)
        print(f"  Run {i}: {result['FindingCount']} findings, "
              f"score={result['RiskScores'].get('OverallRiskScore', 'N/A')}, "
              f"{elapsed:.2f}s")

        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        with open(run_dir / "risk-analysis.json", "w", encoding="utf-8") as fh:
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
        description="PostureIQ — Risk Analysis Determinism Validation",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to risk-evidence.json from a prior run")
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
