#!/usr/bin/env python
"""
CLI entry-point for Attack Path Detection.

Usage:
  # Standalone — collects evidence via ARG + Graph
  python run_attack_path.py --tenant <tenant-id>

  # Reuse evidence from a previous run
  python run_attack_path.py --tenant <tenant-id> --evidence output/<date>/raw-evidence.json

  # Custom output directory
  python run_attack_path.py --tenant <tenant-id> --output-dir output/my-attack-paths

  # Filter by minimum severity
  python run_attack_path.py --tenant <tenant-id> --min-severity high

  # CI/CD gate mode (exit non-zero if severity ≥ threshold)
  python run_attack_path.py --tenant <tenant-id> --fail-on-severity critical

  # Compare with previous run for trend analysis
  python run_attack_path.py --tenant <tenant-id> --previous-run output/<date>/Attack-Path-Detection/attack-path-assessment.json

  # Quiet mode (JSON only)
  python run_attack_path.py --tenant <tenant-id> -q

  # Choose output formats
  python run_attack_path.py --tenant <tenant-id> --format json,html,excel
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.attack_path_engine import run_attack_path_assessment

_SEV_BADGE = {
    "critical": "\033[91m[CRITICAL]\033[0m",
    "high": "\033[93m[HIGH]\033[0m",
    "medium": "\033[33m[MEDIUM]\033[0m",
    "low": "\033[37m[LOW]\033[0m",
    "informational": "\033[90m[INFO]\033[0m",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _print_header(title: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")


def _print_console_summary(assessment: dict) -> None:
    summary = assessment.get("Summary", {})
    paths = assessment.get("Paths", [])

    _print_header("ATTACK PATH DETECTION — RESULTS")

    score = summary.get("OverallRiskScore", 0)
    sev = summary.get("OverallSeverity", "informational").upper()
    total = summary.get("TotalPaths", 0)
    counts = summary.get("SeverityCounts", {})

    print(f"  Overall Risk Score: {score}/100 ({sev})")
    print(f"  Total Attack Paths: {total}")
    print(f"  Severity: Critical={counts.get('critical', 0)}  "
          f"High={counts.get('high', 0)}  Medium={counts.get('medium', 0)}  "
          f"Low={counts.get('low', 0)}")

    # Top 5 paths
    top = sorted(paths, key=lambda p: -p.get("RiskScore", 0))[:5]
    if top:
        print(f"\n  Top {len(top)} Attack Paths:")
        for i, p in enumerate(top, 1):
            sev_low = p.get("Severity", "informational").lower()
            badge = _SEV_BADGE.get(sev_low, f"[{sev_low.upper()}]")
            chain = p.get("Chain", "")
            if len(chain) > 80:
                chain = chain[:77] + "..."
            print(f"    {i}. {badge} (Score {p.get('RiskScore', 0)}) {chain}")

    # MITRE coverage
    mitre = summary.get("MitreTechniques", [])
    if mitre:
        print(f"\n  MITRE ATT&CK Techniques: {len(mitre)}")
        for t in mitre[:5]:
            print(f"    - {t.get('Technique', '')} ({t.get('Count', 0)} paths)")

    # Trend
    trend = summary.get("Trend")
    if trend:
        d = trend.get("Direction", "stable")
        arrow = "↓" if d == "improved" else ("↑" if d == "worsened" else "→")
        print(f"\n  Trend: {arrow} {d.capitalize()}")
        print(f"    New: +{trend['NewPaths']}  Resolved: -{trend['ResolvedPaths']}")


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Attack Path Detection — identify exploitable attack chains in your Azure/Entra environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to pre-collected evidence JSON (skips live collection)")
    parser.add_argument("--output-dir", help="Custom output directory (default: output/<timestamp>/Attack-Path-Detection)")
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "informational"],
                        default="informational", help="Minimum severity to include in reports (default: informational)")
    parser.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low"],
                        help="Exit non-zero if any path meets or exceeds this severity (CI/CD gate)")
    parser.add_argument("--previous-run", help="Path to previous assessment JSON for trend comparison")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console output (JSON only)")
    parser.add_argument("--format", default="json,html,excel",
                        help="Comma-separated output formats: json,html,excel (default: json,html,excel)")
    args = parser.parse_args()

    formats = [f.strip().lower() for f in args.format.split(",")]

    if not args.quiet:
        _print_header("ATTACK PATH DETECTION")
        print(f"  Tenant:  {args.tenant}")
        print(f"  Formats: {', '.join(sorted(formats))}")

    # ── Run assessment (orchestrator handles evidence, reports, output) ──
    t0 = time.time()
    if not args.quiet:
        print("\n  Running attack path detection...")

    assessment = await run_attack_path_assessment(
        tenant_id=args.tenant,
        evidence_path=args.evidence,
        output_dir=args.output_dir,
        min_severity=args.min_severity,
        previous_run=args.previous_run,
        formats=formats,
        quiet=args.quiet,
    )
    elapsed = time.time() - t0

    if not args.quiet:
        print(f"  Completed in {elapsed:.1f}s")
        _print_console_summary(assessment)

    # ── CI/CD gate ───────────────────────────────────────────────────
    if args.fail_on_severity:
        threshold = _SEV_ORDER.get(args.fail_on_severity, 999)
        for p in assessment.get("Paths", []):
            ps = _SEV_ORDER.get(p.get("Severity", "informational").lower(), 4)
            if ps <= threshold:
                if not args.quiet:
                    print(f"\n  GATE FAILED: Found path with severity "
                          f"{p['Severity'].upper()} (threshold: {args.fail_on_severity.upper()})")
                return 1

    if not args.quiet:
        print("\n  Done.\n")
    return 0


def main() -> None:
    rc = asyncio.run(_main())
    sys.exit(rc)


if __name__ == "__main__":
    main()
