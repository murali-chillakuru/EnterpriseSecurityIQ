"""
query_frameworks.advisor — Security context enrichment for Cloud Explorer.

Loads self-contained JSON data from this directory and returns a compact
enrichment string for a given result_family. No external dependencies.
"""

from __future__ import annotations

import json
import pathlib
from functools import lru_cache
from typing import Any

_DATA_DIR = pathlib.Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def _load_json(filename: str) -> dict[str, Any]:
    """Load a JSON file from the query_frameworks directory (cached)."""
    fp = _DATA_DIR / filename
    if not fp.exists():
        return {}
    with open(fp, "r", encoding="utf-8") as f:
        return json.load(f)


def _framework_map() -> dict[str, Any]:
    return _load_json("resource-framework-map.json")


def _risk_indicators() -> dict[str, Any]:
    return _load_json("risk-indicators.json")


def _data_security() -> dict[str, Any]:
    return _load_json("data-security-context.json")


def _ai_security() -> dict[str, Any]:
    return _load_json("ai-security-context.json")


def _copilot_relevance() -> dict[str, Any]:
    return _load_json("copilot-relevance.json")


def _rbac_risk() -> dict[str, Any]:
    return _load_json("rbac-risk-indicators.json")


def get_security_context(result_family: str) -> str:
    """Return a compact security enrichment string for the given result_family.

    This is injected into the LLM formatting pass in Cloud Explorer mode
    so the model can annotate search results with compliance and risk context.
    Returns empty string if the family has no enrichment data.
    """
    family = result_family.lower().strip()
    parts: list[str] = []

    # 1. Compliance framework controls
    fmap = _framework_map()
    if family in fmap:
        controls = fmap[family]
        top_frameworks = []
        for fw in ("CIS", "NIST-800-53", "ISO-27001", "PCI-DSS", "MCSB"):
            if fw in controls:
                top_frameworks.append(f"{fw}: {', '.join(controls[fw][:3])}")
        if top_frameworks:
            parts.append("Compliance: " + " | ".join(top_frameworks))

    # 2. Risk indicators
    risk = _risk_indicators()
    if family in risk:
        r = risk[family]
        score = min(100, int((r["severity"] * r["exploitability"] * r["blast_radius"] / 4.0) * 100 / 25))
        top_risks = r.get("top_risks", [])[:3]
        parts.append(f"Risk Score: {score}/100 — Top risks: {'; '.join(top_risks)}")

    # 3. Data security context
    dsec = _data_security()
    if family in dsec:
        d = dsec[family]
        priority = d.get("priority", "medium")
        enc = d.get("encryption", [])[:2]
        parts.append(f"Data Security ({priority}): {'; '.join(enc)}")

    # 4. AI security context (only for relevant families)
    ai_ctx = _ai_security()
    if family in ai_ctx:
        a = ai_ctx[family]
        if "nist_ai_rmf" in a:
            concerns = a["nist_ai_rmf"].get("key_concerns", [])[:2]
            parts.append(f"AI Security (NIST AI RMF): {'; '.join(concerns)}")
        if "owasp_llm" in a:
            concerns = a["owasp_llm"].get("key_concerns", [])[:2]
            parts.append(f"AI Security (OWASP LLM): {'; '.join(concerns)}")

    # 5. Copilot readiness relevance
    cop = _copilot_relevance()
    if family in cop:
        c = cop[family]
        relevance = c.get("relevance", "low")
        risks = c.get("copilot_risks", [])[:2]
        parts.append(f"Copilot Readiness ({relevance}): {'; '.join(risks)}")

    # 6. RBAC risk indicators
    rbac = _rbac_risk()
    if family in rbac:
        rb = rbac[family]
        risk_level = rb.get("risk_level", "medium")
        checks = rb.get("key_checks", [])[:2]
        parts.append(f"RBAC Risk ({risk_level}): {'; '.join(checks)}")

    if not parts:
        return ""

    return "SECURITY CONTEXT for " + family.upper() + " resources:\n" + "\n".join(f"• {p}" for p in parts)
