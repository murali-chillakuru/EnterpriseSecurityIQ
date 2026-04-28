"""
Attack Path Detection — Engine façade.

Re-exports the orchestrator entry point and key evaluator modules
so external code can do:

    from app.attack_path_engine import run_attack_path_assessment
"""
from __future__ import annotations

from app.attackpath_orchestrator import run_attack_path_assessment
from app.attackpath_evaluators.scoring import compute_risk_summary, filter_by_severity

__all__ = [
    "run_attack_path_assessment",
    "compute_risk_summary",
    "filter_by_severity",
]
