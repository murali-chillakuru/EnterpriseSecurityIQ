"""Shared finding constructor and constants for AI Agent Security evaluators."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}


def _as_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    platform: str = "cross-cutting",
    affected_resources: list[dict] | None = None,
    remediation: dict | None = None,
    compliance_status: str = "gap",
) -> dict:
    """Create a standardised AI agent security finding dict."""
    return {
        "AgentSecurityFindingId": str(uuid.uuid4()),
        "Category": category,
        "Subcategory": subcategory,
        "Platform": platform,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "ComplianceStatus": compliance_status,
        "AffectedResources": affected_resources or [],
        "AffectedCount": len(affected_resources) if affected_resources else 0,
        "Remediation": remediation or {},
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }


def _unable_to_assess(
    category: str,
    evidence_types: list[str],
    reason: str = "",
    platform: str = "foundry",
) -> dict:
    """Return an 'unable to assess' finding when expected evidence is absent.

    This makes the gap visible in the report rather than silently returning
    an empty list, so users know which areas could not be evaluated and why.
    """
    types_str = ", ".join(evidence_types)
    return _as_finding(
        category=category,
        subcategory="unable_to_assess",
        title=f"Unable to assess: {category.replace('_', ' ').title()}",
        description=(
            reason or
            f"No evidence of type [{types_str}] was collected. "
            f"This could mean: (a) the resource type does not exist in the environment, "
            f"(b) the collector lacked permissions (403), or (c) collection timed out. "
            f"Re-run with full permissions or verify the resource exists."
        ),
        severity="informational",
        platform=platform,
        compliance_status="unable_to_assess",
    )

