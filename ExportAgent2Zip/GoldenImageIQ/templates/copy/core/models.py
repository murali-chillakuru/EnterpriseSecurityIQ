"""Core data models — EvidenceRecord, FindingRecord, AssessmentResult."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

# Severity weights used in scoring
SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


@dataclass
class EvidenceRecord:
    evidence_type: str
    source: str
    collector: str
    data: dict[str, Any] = field(default_factory=dict)
    resource_id: str = ""
    resource_type: str = ""
    description: str = ""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "EvidenceId": self.evidence_id,
            "EvidenceType": self.evidence_type,
            "Source": self.source,
            "Collector": self.collector,
            "Description": self.description,
            "CollectedAt": self.collected_at,
            "ResourceId": self.resource_id,
            "ResourceType": self.resource_type,
            "Data": self.data,
        }


@dataclass
class FindingRecord:
    control_id: str
    framework: str
    status: str
    severity: str
    domain: str
    control_title: str = ""
    description: str = ""
    recommendation: str = ""
    resource_id: str = ""
    resource_type: str = ""
    supporting_evidence: list[dict] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def finding_id(self) -> str:
        """Deterministic UUID5 from control_id + framework + resource_id."""
        seed = f"{self.control_id}:{self.framework}:{self.resource_id}"
        return str(uuid.uuid5(uuid.NAMESPACE_OID, seed))

    @property
    def severity_weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity.lower(), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "FindingId": self.finding_id,
            "ControlId": self.control_id,
            "Framework": self.framework,
            "ControlTitle": self.control_title,
            "Status": self.status,
            "Severity": self.severity,
            "Domain": self.domain,
            "Description": self.description,
            "Recommendation": self.recommendation,
            "ResourceId": self.resource_id,
            "ResourceType": self.resource_type,
            "SupportingEvidence": self.supporting_evidence,
            "EvaluatedAt": self.evaluated_at,
        }


@dataclass
class AssessmentResult:
    project_name: str
    run_id: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
    evidence: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    score: float = 0.0
    grade: str = "N/A"

    def compute_score(self) -> None:
        """Weighted severity scoring: 100 minus penalty points."""
        if not self.findings:
            self.score = 100.0
            self.grade = "A"
            return
        total_weight = sum(
            SEVERITY_WEIGHTS.get(f.get("Severity", "").lower(), 0)
            for f in self.findings
            if f.get("Status") == "non_compliant"
        )
        self.score = max(0.0, 100.0 - total_weight)
        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 40:
            self.grade = "D"
        else:
            self.grade = "F"
