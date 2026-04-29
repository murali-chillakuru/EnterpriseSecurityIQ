#!/usr/bin/env python
"""
Live determinism validation for Data Security Assessment.

Collects evidence from the real tenant once, then re-runs the
analysis pipeline 3 times from the same captured evidence and
compares all outputs for consistency.

Usage:
  python run_ds_determinism_check.py --tenant <tenant-id>
  python run_ds_determinism_check.py --tenant <tenant-id> --evidence output/<ts>/ds-evidence.json
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
from app.datasec_evaluators.storage import analyze_storage_exposure
from app.datasec_evaluators.database import analyze_database_security
from app.datasec_evaluators.cosmosdb import analyze_cosmosdb_security
from app.datasec_evaluators.postgres_mysql import analyze_postgres_mysql_security
from app.datasec_evaluators.keyvault import analyze_keyvault_hygiene
from app.datasec_evaluators.encryption import analyze_encryption_posture
from app.datasec_evaluators.data_access import analyze_data_access_controls
from app.datasec_evaluators.private_endpoints import analyze_private_endpoints
from app.datasec_evaluators.purview import analyze_purview_security
from app.datasec_evaluators.file_sync import analyze_file_sync_security
from app.datasec_evaluators.m365_dlp import analyze_m365_dlp
from app.datasec_evaluators.data_classification import analyze_data_classification_security
from app.datasec_evaluators.backup_dr import analyze_backup_dr
from app.datasec_evaluators.containers import analyze_container_security
from app.datasec_evaluators.network_segmentation import analyze_network_segmentation
from app.datasec_evaluators.data_residency import analyze_data_residency
from app.datasec_evaluators.threat_detection import analyze_threat_detection
from app.datasec_evaluators.sharepoint import analyze_sharepoint_governance
from app.datasec_evaluators.m365_lifecycle import analyze_m365_data_lifecycle
from app.datasec_evaluators.dlp_alerts import analyze_dlp_alert_effectiveness
from app.datasec_evaluators.redis import analyze_redis_security
from app.datasec_evaluators.messaging import analyze_messaging_security
from app.datasec_evaluators.ai_services import analyze_ai_services_security
from app.datasec_evaluators.data_factory import analyze_data_factory_security
from app.datasec_evaluators.managed_identity import analyze_managed_identity_deep
from app.datasec_evaluators.platform_services import (
    analyze_sql_mi_security, analyze_app_config_security,
    analyze_cert_lifecycle, analyze_databricks_security,
    analyze_apim_security, analyze_frontdoor_security,
    analyze_secret_sprawl, analyze_firewall_appgw_security,
    analyze_bastion_security, analyze_policy_compliance,
    analyze_defender_score,
)
from app.datasec_evaluators.identity_access import (
    analyze_stale_permissions, analyze_data_exfiltration,
    analyze_conditional_access_pim,
)
from app.datasec_evaluators.advanced_analytics import (
    analyze_blast_radius, analyze_data_flow,
    analyze_config_drift, analyze_supply_chain_risk,
)
from app.datasec_evaluators.scoring import compute_data_security_scores
from app.datasec_evaluators.enrichment import (
    enrich_compliance_mapping, enrich_per_resource_details,
    consolidate_findings,
)
from app.logger import log


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_ANALYZERS = [
    ("storage_exposure",       analyze_storage_exposure),
    ("database_security",      analyze_database_security),
    ("cosmosdb_security",      analyze_cosmosdb_security),
    ("postgres_mysql",         analyze_postgres_mysql_security),
    ("keyvault_hygiene",       analyze_keyvault_hygiene),
    ("encryption_posture",     analyze_encryption_posture),
    ("data_access_controls",   analyze_data_access_controls),
    ("private_endpoints",      analyze_private_endpoints),
    ("purview_security",       analyze_purview_security),
    ("file_sync_security",     analyze_file_sync_security),
    ("m365_dlp",               analyze_m365_dlp),
    ("data_classification",    analyze_data_classification_security),
    ("backup_dr",              analyze_backup_dr),
    ("container_security",     analyze_container_security),
    ("network_segmentation",   analyze_network_segmentation),
    ("data_residency",         analyze_data_residency),
    ("threat_detection",       analyze_threat_detection),
    ("sharepoint_governance",  analyze_sharepoint_governance),
    ("m365_data_lifecycle",    analyze_m365_data_lifecycle),
    ("dlp_alert_effectiveness", analyze_dlp_alert_effectiveness),
    ("redis_security",         analyze_redis_security),
    ("messaging_security",     analyze_messaging_security),
    ("ai_services_security",   analyze_ai_services_security),
    ("data_factory_security",  analyze_data_factory_security),
    ("managed_identity_deep",  analyze_managed_identity_deep),
    ("sql_mi_security",        analyze_sql_mi_security),
    ("app_config_security",    analyze_app_config_security),
    ("cert_lifecycle",         analyze_cert_lifecycle),
    ("databricks_security",    analyze_databricks_security),
    ("apim_security",          analyze_apim_security),
    ("frontdoor_security",     analyze_frontdoor_security),
    ("secret_sprawl",          analyze_secret_sprawl),
    ("firewall_appgw",         analyze_firewall_appgw_security),
    ("bastion_security",       analyze_bastion_security),
    ("policy_compliance",      analyze_policy_compliance),
    ("defender_score",         analyze_defender_score),
    ("stale_permissions",      analyze_stale_permissions),
    ("data_exfiltration",      analyze_data_exfiltration),
    ("conditional_access_pim", analyze_conditional_access_pim),
    ("supply_chain_risk",      analyze_supply_chain_risk),
]


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _run_analysis(evidence_index: dict[str, list[dict]], run_label: str) -> dict:
    """Run the full analysis pipeline on evidence and return results."""
    print(f"\n  Running analysis ({run_label}) …")
    all_findings: list[dict] = []
    for name, fn in _ANALYZERS:
        findings = fn(evidence_index)
        all_findings.extend(findings)
        if findings:
            print(f"    {name}: {len(findings)} findings")

    # Enrichment (same as orchestrator)
    enrich_compliance_mapping(all_findings)
    enrich_per_resource_details(all_findings)
    all_findings = consolidate_findings(all_findings)

    # Deterministic sort (same as orchestrator)
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _SEVERITY_ORDER.get(f.get("Severity", "medium").lower(), 9),
        )
    )
    for _f in all_findings:
        _f.get("AffectedResources", []).sort(
            key=lambda r: r.get("ResourceId", r.get("Name", ""))
        )

    scores = compute_data_security_scores(all_findings)
    blast_radius = analyze_blast_radius(evidence_index, all_findings)
    data_flows = analyze_data_flow(evidence_index)

    print(f"    Total (post-consolidation): {len(all_findings)} findings")

    return {
        "RunLabel": run_label,
        "FindingCount": len(all_findings),
        "Findings": all_findings,
        "DataSecurityScores": scores,
        "BlastRadius": blast_radius,
        "DataFlows": data_flows,
    }


def _strip_volatile(obj):
    """Recursively strip timestamp and volatile fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k not in ("DetectedAt", "AssessedAt", "RunLabel", "AssessmentId")
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
        "Verdict": "UNKNOWN",
    }

    # ── Run summaries ────────────────────────────────────────────
    for r in runs:
        scores = r.get("DataSecurityScores", {})
        report["Runs"].append({
            "Label": r["RunLabel"],
            "FindingCount": r["FindingCount"],
            "OverallScore": scores.get("OverallScore"),
            "SecurityPosture": scores.get("SecurityPosture"),
        })

    # ── Finding ID comparison (DataSecurityFindingId is deterministic) ──
    id_sets = [
        set(f["DataSecurityFindingId"] for f in r["Findings"]
            if "DataSecurityFindingId" in f)
        for r in runs
    ]
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
        idx = {f["DataSecurityFindingId"]: f for f in r["Findings"]
               if "DataSecurityFindingId" in f}
        findings_by_id.append(idx)

    skip_keys = {"DetectedAt", "AssessedAt", "RunLabel", "AssessmentId"}
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
    scores = [r.get("DataSecurityScores", {}) for r in runs]
    overall_scores = [s.get("OverallScore") for s in scores]
    postures = [s.get("SecurityPosture") for s in scores]
    sev_dists = [s.get("SeverityDistribution") for s in scores]
    report["ScoreComparison"] = {
        "OverallScoresIdentical": len(set(str(s) for s in overall_scores)) == 1,
        "OverallScores": overall_scores,
        "PosturesIdentical": len(set(str(s) for s in postures)) == 1,
        "Postures": postures,
        "SeverityDistributionsIdentical": sev_dists[0] == sev_dists[1] == sev_dists[2] if all(sev_dists) else False,
    }

    # ── Full JSON comparison (excluding volatile fields) ─────────
    clean_runs = [_strip_volatile(r) for r in runs]
    jsons = [json.dumps(c, sort_keys=True, default=str) for c in clean_runs]
    full_json_match = (jsons[0] == jsons[1] == jsons[2])

    # ── Verdict ──────────────────────────────────────────────────
    all_pass = (
        all_ids_match
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
              f"Score={r['OverallScore']} | Posture={r['SecurityPosture']}")

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
    print(f"  Postures: {'✓ All identical' if sc['PosturesIdentical'] else '✗ DIFFER'} ({sc['Postures']})")
    print(f"  Severity Dist: {'✓ All identical' if sc['SeverityDistributionsIdentical'] else '✗ DIFFER'}")
    print(f"  Full JSON Match: {'✓' if report['FullJsonMatch'] else '✗'}")

    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("PostureIQ — Data Security Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_ds_{ts}"
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
        from app.datasec_orchestrator import _ds_lightweight_collect, _ds_arm_enrich
        evidence_index = await _ds_lightweight_collect(creds, subscriptions)
        await _ds_arm_enrich(creds, evidence_index)
        rec_count = sum(len(v) for v in evidence_index.values())
        print(f"  Collected {rec_count} evidence records")

        # Save evidence for reuse
        evidence_flat: list[dict] = []
        for records in evidence_index.values():
            if not isinstance(records, list):
                continue
            evidence_flat.extend(records)
        evidence_path = base_dir / "ds-evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fh:
            json.dump(evidence_flat, fh, indent=2, default=str)
        print(f"  Evidence saved: {evidence_path}")

    print(f"\n  Evidence types: {len(evidence_index)}")
    for etype, records in sorted(evidence_index.items()):
        if isinstance(records, list):
            print(f"    {etype}: {len(records)} records")

    # ── Step 2: Run analysis 3 times ─────────────────────────────
    _print_header("RUNNING 3 ANALYSIS PASSES")

    runs: list[dict] = []
    for i in range(1, 4):
        start = time.monotonic()
        result = _run_analysis(evidence_index, f"Run {i}")
        elapsed = time.monotonic() - start
        runs.append(result)
        print(f"  Run {i}: {result['FindingCount']} findings, "
              f"score={result['DataSecurityScores'].get('OverallScore', 'N/A')}, "
              f"{elapsed:.2f}s")

        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        with open(run_dir / "data-security-assessment.json", "w", encoding="utf-8") as fh:
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
        description="PostureIQ — Data Security Determinism Validation",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to ds-evidence.json from a prior run")
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
