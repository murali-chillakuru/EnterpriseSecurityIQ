"""
Attack Path Detection — Data Exposure evaluator.

Phase 3 M365/SPO: SharePoint Online anonymous sharing links and
oversharing configurations that expose data externally.
"""
from __future__ import annotations

from app.attackpath_evaluators.finding import ap_path


def analyze_data_exposure(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Detect SPO anonymous sharing and oversharing paths."""
    paths: list[dict] = []

    spo_items = evidence_index.get("spo-sharing-links", [])
    for item in spo_items:
        d = item.get("Data", {})
        site_url = d.get("SiteUrl", d.get("siteUrl", "unknown"))
        sharing_cap = d.get("SharingCapability", d.get("sharingCapability", ""))
        anon_count = d.get("AnonymousLinkCount", d.get("anonymousLinkCount", 0))
        total_external = d.get("ExternalUserCount", d.get("externalUserCount", 0))

        # Anonymous sharing enabled
        if sharing_cap in ("ExternalUserAndGuestSharing", "ExternalUserSharingOnly"):
            score = 85 if anon_count > 10 else 70
            paths.append(ap_path(
                path_type="data_exposure",
                subtype="spo_anonymous_sharing",
                chain=(
                    f"SharePoint site '{site_url}' has sharing set to "
                    f"'{sharing_cap}' with {anon_count} anonymous links "
                    f"and {total_external} external users. Anonymous links "
                    f"require no authentication for access."
                ),
                risk_score=score,
                severity="high" if score >= 80 else "medium",
                resource_name=site_url,
                resource_type="SharePoint Site",
                exposure=f"{sharing_cap} ({anon_count} anon links)",
                mitre_technique="T1213.002",
                mitre_tactic="Collection",
                remediation="Disable anonymous sharing; use authenticated external sharing with expiration policies.",
                ms_learn_url="https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off",
                chain_nodes=[
                    {"type": "resource", "label": f"SPO: {site_url[:25]}"},
                    {"type": "config", "label": sharing_cap},
                    {"type": "exposure", "label": f"{anon_count} anon links"},
                ],
            ))

    # Also check tenant-level oversharing from Graph config (if collected)
    tenant_spo = evidence_index.get("spo-tenant-config", [])
    for item in tenant_spo:
        d = item.get("Data", {})
        if d.get("SharingCapability") == "ExternalUserAndGuestSharing":
            paths.append(ap_path(
                path_type="data_exposure",
                subtype="spo_tenant_anonymous",
                chain=(
                    "Tenant-level SharePoint sharing is set to the most permissive level "
                    "(ExternalUserAndGuestSharing). Any site owner can create anonymous links."
                ),
                risk_score=80,
                severity="high",
                resource_type="SharePoint Tenant",
                exposure="Most permissive sharing level",
                mitre_technique="T1213.002",
                mitre_tactic="Collection",
                remediation="Restrict tenant sharing to 'New and existing guests' or 'Existing guests only'.",
                ms_learn_url="https://learn.microsoft.com/sharepoint/manage-sharing-for-your-sharepoint-online-environment",
                chain_nodes=[
                    {"type": "config", "label": "Tenant SPO sharing"},
                    {"type": "exposure", "label": "Most permissive level"},
                    {"type": "impact", "label": "Any site can share anonymously"},
                ],
            ))

    return paths
