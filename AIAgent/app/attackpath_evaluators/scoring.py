"""
Attack Path Detection — Risk Scoring & Severity Aggregation.

Computes overall risk posture from all detected attack paths,
assigns severity tiers, and produces summary statistics.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import SEVERITY_WEIGHTS, SEVERITY_ORDER


def compute_risk_summary(paths: list[dict], *, previous_paths: list[dict] | None = None) -> dict:
    """Compute aggregated risk summary from detected attack paths.

    Returns a summary dict with severity counts, overall score,
    top paths, MITRE coverage, and optional trend analysis vs *previous_paths*.
    """
    if not paths:
        return {
            "TotalPaths": 0,
            "OverallRiskScore": 0,
            "OverallSeverity": "informational",
            "SeverityCounts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
            "PathsByType": {},
            "Top5Paths": [],
            "MitreTechniques": [],
            "Trend": None,
        }

    # ── Severity counts ──────────────────────────────────────────────
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for p in paths:
        sev = p.get("Severity", "informational").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # ── Paths by type ────────────────────────────────────────────────
    by_type: dict[str, int] = {}
    for p in paths:
        ptype = p.get("Type", "unknown")
        by_type[ptype] = by_type.get(ptype, 0) + 1

    # ── Overall risk score (weighted average, capped at 100) ─────────
    if paths:
        weighted_sum = sum(
            p.get("RiskScore", 0) * SEVERITY_WEIGHTS.get(p.get("Severity", "informational").lower(), 1.0)
            for p in paths
        )
        weight_total = sum(
            SEVERITY_WEIGHTS.get(p.get("Severity", "informational").lower(), 1.0)
            for p in paths
        )
        overall_score = round(weighted_sum / weight_total) if weight_total > 0 else 0
    else:
        overall_score = 0

    # ── Overall severity from the worst finding ──────────────────────
    overall_severity = "informational"
    for p in paths:
        sev = p.get("Severity", "informational").lower()
        if SEVERITY_ORDER.get(sev, 99) < SEVERITY_ORDER.get(overall_severity, 99):
            overall_severity = sev

    # ── Top 5 paths by risk score ────────────────────────────────────
    sorted_paths = sorted(paths, key=lambda p: -p.get("RiskScore", 0))
    top5 = sorted_paths[:5]

    # ── MITRE technique coverage ─────────────────────────────────────
    techniques: dict[str, int] = {}
    for p in paths:
        t = p.get("MitreTechnique", "")
        if t:
            techniques[t] = techniques.get(t, 0) + 1
    mitre_list = [{"Technique": t, "Count": c} for t, c in sorted(techniques.items(), key=lambda x: -x[1])]

    # ── Trend analysis vs previous run ───────────────────────────────
    trend = None
    if previous_paths is not None:
        prev_ids = {p.get("AttackPathId") for p in previous_paths}
        curr_ids = {p.get("AttackPathId") for p in paths}
        new_ids = curr_ids - prev_ids
        resolved_ids = prev_ids - curr_ids
        persistent_ids = curr_ids & prev_ids
        trend = {
            "NewPaths": len(new_ids),
            "ResolvedPaths": len(resolved_ids),
            "PersistentPaths": len(persistent_ids),
            "PreviousTotal": len(previous_paths),
            "CurrentTotal": len(paths),
            "Direction": (
                "improved" if len(paths) < len(previous_paths) else
                "worsened" if len(paths) > len(previous_paths) else
                "stable"
            ),
        }

    return {
        "TotalPaths": len(paths),
        "OverallRiskScore": overall_score,
        "OverallSeverity": overall_severity,
        "SeverityCounts": severity_counts,
        "PathsByType": by_type,
        "Top5Paths": top5,
        "MitreTechniques": mitre_list,
        "Trend": trend,
    }


def filter_by_severity(paths: list[dict], min_severity: str) -> list[dict]:
    """Filter paths keeping only those at or above *min_severity*."""
    threshold = SEVERITY_ORDER.get(min_severity.lower(), 99)
    return [p for p in paths if SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 99) <= threshold]
