"""Base collector helpers and evidence record factory."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def make_evidence(
    evidence_type: str,
    source: str,
    collector: str,
    data: dict[str, Any],
    resource_id: str = "",
    resource_type: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Create a standardised evidence record dict."""
    return {
        "EvidenceId": str(uuid.uuid4()),
        "EvidenceType": evidence_type,
        "Source": source,
        "Collector": collector,
        "Description": description,
        "CollectedAt": datetime.now(timezone.utc).isoformat(),
        "ResourceId": resource_id,
        "ResourceType": resource_type,
        "Data": data,
    }
