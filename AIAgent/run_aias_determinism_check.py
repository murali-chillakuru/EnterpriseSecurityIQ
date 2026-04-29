#!/usr/bin/env python
"""
Live determinism validation for AI Agent Security Assessment.

Collects evidence from the real tenant once, then re-runs the
analysis pipeline 3 times from the same captured evidence and
compares all outputs for consistency.

NOTE: AgentSecurityFindingId uses uuid4() (random), so findings are
matched by (Category, Subcategory, Platform) composite key instead.

Usage:
  python run_aias_determinism_check.py --tenant <tenant-id>
  python run_aias_determinism_check.py --tenant <tenant-id> --evidence output/<ts>/aias-evidence.json
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
# A. Copilot Studio
from app.aiagentsec_evaluators.copilot_studio import (
    analyze_cs_authentication, analyze_cs_data_connectors,
    analyze_cs_logging, analyze_cs_channels,
)
# A-ext. Copilot Studio Extended
from app.aiagentsec_evaluators.copilot_studio_ext import (
    analyze_cs_knowledge_sources, analyze_cs_generative_ai,
    analyze_cs_governance, analyze_cs_connector_security,
)
# A-ext. Copilot Studio DLP Deep Dive
from app.aiagentsec_evaluators.copilot_studio_dlp import (
    analyze_cs_dlp_depth, analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced, analyze_cs_audit_compliance,
    analyze_cs_dataverse_security, analyze_cs_readiness_crosscheck,
)
# B. Microsoft Foundry Infrastructure
from app.aiagentsec_evaluators.foundry_infra import (
    analyze_foundry_network, analyze_foundry_identity,
    analyze_foundry_content_safety, analyze_foundry_deployments,
    analyze_foundry_governance,
)
# B-ext. Microsoft Foundry Extended
from app.aiagentsec_evaluators.foundry_ext import (
    analyze_foundry_compute, analyze_foundry_datastores,
    analyze_foundry_endpoints, analyze_foundry_registry,
    analyze_foundry_connections, analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
)
# B-new. Microsoft Foundry New Categories
from app.aiagentsec_evaluators.foundry_new import (
    analyze_foundry_prompt_shields, analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration, analyze_foundry_agent_identity,
    analyze_foundry_agent_application, analyze_foundry_mcp_tools,
    analyze_foundry_tool_security, analyze_foundry_guardrails,
    analyze_foundry_hosted_agents, analyze_foundry_data_resources,
    analyze_foundry_observability, analyze_foundry_lifecycle,
)
# C. Custom Agent Security
from app.aiagentsec_evaluators.custom_ai import (
    analyze_custom_api_security, analyze_custom_data_residency,
    analyze_custom_content_leakage,
)
# D. Entra AI Identity
from app.aiagentsec_evaluators.entra_ai import (
    analyze_entra_ai_service_principals, analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent, analyze_entra_ai_workload_identity,
    analyze_entra_ai_cross_tenant, analyze_entra_ai_privileged_access,
)
# E. AI Infrastructure Security
from app.aiagentsec_evaluators.ai_infra import (
    analyze_ai_diagnostics, analyze_ai_model_governance,
    analyze_ai_threat_protection, analyze_ai_data_governance,
)
# F. Agent Orchestration & Platform Security
from app.aiagentsec_evaluators.ai_defense import (
    analyze_ai_defender_coverage, analyze_ai_policy_compliance,
    analyze_agent_communication, analyze_agent_governance,
)
from app.aiagentsec_evaluators.scoring import compute_agent_security_scores
from app.aiagentsec_evaluators.enrichment import enrich_compliance_mapping
from app.logger import log


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_ANALYZERS = [
    # A. Copilot Studio
    ("cs_authentication",    analyze_cs_authentication),
    ("cs_data_connectors",   analyze_cs_data_connectors),
    ("cs_logging",           analyze_cs_logging),
    ("cs_channels",          analyze_cs_channels),
    ("cs_knowledge_sources", analyze_cs_knowledge_sources),
    ("cs_generative_ai",     analyze_cs_generative_ai),
    ("cs_governance",        analyze_cs_governance),
    ("cs_connector_security", analyze_cs_connector_security),
    ("cs_dlp_depth",         analyze_cs_dlp_depth),
    ("cs_environment_governance", analyze_cs_environment_governance),
    ("cs_agent_security_advanced", analyze_cs_agent_security_advanced),
    ("cs_audit_compliance",  analyze_cs_audit_compliance),
    ("cs_dataverse_security", analyze_cs_dataverse_security),
    ("cs_readiness_crosscheck", analyze_cs_readiness_crosscheck),
    # B. Microsoft Foundry
    ("foundry_network",      analyze_foundry_network),
    ("foundry_identity",     analyze_foundry_identity),
    ("foundry_content_safety", analyze_foundry_content_safety),
    ("foundry_deployments",  analyze_foundry_deployments),
    ("foundry_governance",   analyze_foundry_governance),
    ("foundry_compute",      analyze_foundry_compute),
    ("foundry_datastores",   analyze_foundry_datastores),
    ("foundry_endpoints",    analyze_foundry_endpoints),
    ("foundry_registry",     analyze_foundry_registry),
    ("foundry_connections",  analyze_foundry_connections),
    ("foundry_serverless",   analyze_foundry_serverless),
    ("foundry_ws_diagnostics", analyze_foundry_ws_diagnostics),
    ("foundry_prompt_shields", analyze_foundry_prompt_shields),
    ("foundry_model_catalog", analyze_foundry_model_catalog),
    ("foundry_data_exfiltration", analyze_foundry_data_exfiltration),
    ("foundry_agent_identity", analyze_foundry_agent_identity),
    ("foundry_agent_application", analyze_foundry_agent_application),
    ("foundry_mcp_tools",    analyze_foundry_mcp_tools),
    ("foundry_tool_security", analyze_foundry_tool_security),
    ("foundry_guardrails",   analyze_foundry_guardrails),
    ("foundry_hosted_agents", analyze_foundry_hosted_agents),
    ("foundry_data_resources", analyze_foundry_data_resources),
    ("foundry_observability", analyze_foundry_observability),
    ("foundry_lifecycle",    analyze_foundry_lifecycle),
    # C. Custom Agent Security
    ("custom_api_security",  analyze_custom_api_security),
    ("custom_data_residency", analyze_custom_data_residency),
    ("custom_content_leakage", analyze_custom_content_leakage),
    # D. Entra AI Identity
    ("entra_ai_service_principals", analyze_entra_ai_service_principals),
    ("entra_ai_conditional_access", analyze_entra_ai_conditional_access),
    ("entra_ai_consent",     analyze_entra_ai_consent),
    ("entra_ai_workload_identity", analyze_entra_ai_workload_identity),
    ("entra_ai_cross_tenant", analyze_entra_ai_cross_tenant),
    ("entra_ai_privileged_access", analyze_entra_ai_privileged_access),
    # E. AI Infrastructure
    ("ai_diagnostics",       analyze_ai_diagnostics),
    ("ai_model_governance",  analyze_ai_model_governance),
    ("ai_threat_protection", analyze_ai_threat_protection),
    ("ai_data_governance",   analyze_ai_data_governance),
    # F. Agent Orchestration
    ("ai_defender_coverage", analyze_ai_defender_coverage),
    ("ai_policy_compliance", analyze_ai_policy_compliance),
    ("agent_communication",  analyze_agent_communication),
    ("agent_governance",     analyze_agent_governance),
]


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _finding_key(f: dict) -> str:
    """Stable composite key for matching findings across runs."""
    return f"{f.get('Category', '')}|{f.get('Subcategory', '')}|{f.get('Platform', '')}"


def _run_analysis(evidence_index: dict[str, list[dict]], run_label: str) -> dict:
    """Run the full analysis pipeline on evidence and return results."""
    print(f"\n  Running analysis ({run_label}) …")
    all_findings: list[dict] = []
    for name, fn in _ANALYZERS:
        findings = fn(evidence_index)
        all_findings.extend(findings)
        if findings:
            print(f"    {name}: {len(findings)} findings")

    enrich_compliance_mapping(all_findings)

    # Deterministic sort
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            f.get("Platform", ""),
            _SEVERITY_ORDER.get(f.get("Severity", "medium").lower(), 9),
        )
    )

    scores = compute_agent_security_scores(all_findings)

    print(f"    Total: {len(all_findings)} findings")

    return {
        "RunLabel": run_label,
        "FindingCount": len(all_findings),
        "Findings": all_findings,
        "AgentSecurityScores": scores,
    }


def _strip_volatile(obj):
    """Recursively strip timestamp and volatile fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k not in ("DetectedAt", "AssessedAt", "RunLabel",
                         "AgentSecurityFindingId", "AssessmentId")
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
        scores = r.get("AgentSecurityScores", {})
        report["Runs"].append({
            "Label": r["RunLabel"],
            "FindingCount": r["FindingCount"],
            "OverallScore": scores.get("OverallScore"),
            "SecurityPosture": scores.get("SecurityPosture"),
        })

    # ── Finding key comparison ───────────────────────────────────
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

    skip_fields = {"DetectedAt", "AssessedAt", "RunLabel",
                   "AgentSecurityFindingId", "AssessmentId"}
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
    scores = [r.get("AgentSecurityScores", {}) for r in runs]
    overall_scores = [s.get("OverallScore") for s in scores]
    postures = [s.get("SecurityPosture") for s in scores]
    report["ScoreComparison"] = {
        "OverallScoresIdentical": len(set(str(s) for s in overall_scores)) == 1,
        "OverallScores": overall_scores,
        "PosturesIdentical": len(set(str(s) for s in postures)) == 1,
        "Postures": postures,
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
              f"Score={r['OverallScore']} | Posture={r['SecurityPosture']}")

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
    print(f"  Postures: {'✓ All identical' if sc['PosturesIdentical'] else '✗ DIFFER'} ({sc['Postures']})")
    print(f"  Full JSON Match: {'✓' if report['FullJsonMatch'] else '✗'}")

    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("PostureIQ — AI Agent Security Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_aias_{ts}"
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
        from app.aiagentsec_evaluators.collector import _as_collect
        evidence_index = await _as_collect(creds, subscriptions)
        rec_count = sum(len(v) for v in evidence_index.values())
        print(f"  Collected {rec_count} evidence records")

        # Save evidence for reuse
        evidence_flat: list[dict] = []
        for records in evidence_index.values():
            if isinstance(records, list):
                evidence_flat.extend(records)
        evidence_path = base_dir / "aias-evidence.json"
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
              f"score={result['AgentSecurityScores'].get('OverallScore', 'N/A')}, "
              f"{elapsed:.2f}s")

        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        with open(run_dir / "ai-agent-security-assessment.json", "w", encoding="utf-8") as fh:
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
        description="PostureIQ — AI Agent Security Determinism Validation",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to aias-evidence.json from a prior run")
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
