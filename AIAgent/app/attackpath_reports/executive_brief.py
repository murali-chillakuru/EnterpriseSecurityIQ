"""
Attack Path Detection — Executive Brief.

Enterprise-grade C-suite summary with SVG visualizations:
- Ring score gauge + severity donut chart
- 8 KPI cards with color coding
- Attack category breakdown bar chart
- Top 5 critical paths with severity badges
- Remediation impact projection
- Key recommendations with Learn links
- Print-optimized single-page layout
"""
from __future__ import annotations

import html as _html
import math
from datetime import datetime, timezone

_SEVERITY_COLORS = {
    "critical": "#D13438",
    "high": "#FF8C00",
    "medium": "#FFB900",
    "low": "#0078D4",
    "informational": "#6B6B6B",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_TYPE_LABELS = {
    "privilege_escalation": "Privilege Escalation",
    "lateral_movement": "Lateral Movement",
    "exposed_high_value": "Exposed Resources",
    "credential_chain": "Credential Chain",
    "ca_bypass": "CA Bypass",
    "network_pivot": "Network Pivot",
    "pim_escalation": "PIM Escalation",
    "compromised_identity": "Compromised Identity",
    "consent_abuse": "OAuth Abuse",
    "custom_role_escalation": "Custom Role",
    "data_exposure": "Data Exposure",
    "ai_attack_surface": "AI Surface",
    "cross_tenant": "Cross-Tenant",
}


def _esc(text) -> str:
    return _html.escape(str(text)) if text else ""


def _ring_gauge_svg(score: int, size: int = 140) -> str:
    """SVG ring gauge for risk score."""
    center = size // 2
    r = center - 12
    circ = 2 * math.pi * r
    pct = min(score, 100) / 100
    offset = circ * (1 - pct)
    if score >= 80:
        color = _SEVERITY_COLORS["critical"]
    elif score >= 60:
        color = _SEVERITY_COLORS["high"]
    elif score >= 40:
        color = _SEVERITY_COLORS["medium"]
    else:
        color = "#107C10"
    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="Risk Score: {score}">
  <circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="#e0e0e0" stroke-width="12"/>
  <circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="{color}" stroke-width="12"
          stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}" stroke-linecap="round"
          transform="rotate(-90 {center} {center})" style="transition:stroke-dashoffset 1s ease"/>
  <text x="{center}" y="{center - 4}" text-anchor="middle" dominant-baseline="central"
        font-size="32" font-weight="700" fill="{color}">{score}</text>
  <text x="{center}" y="{center + 18}" text-anchor="middle" font-size="9" fill="#666"
        letter-spacing="1.2" text-transform="uppercase">RISK SCORE</text>
</svg>"""


def _donut_svg(counts: dict, size: int = 140) -> str:
    """SVG severity donut chart."""
    center = size // 2
    r = 48
    total = sum(counts.values())
    if total == 0:
        return f'<svg width="{size}" height="{size}"><text x="{center}" y="{center}" text-anchor="middle" fill="#999" font-size="11">No data</text></svg>'
    circ = 2 * math.pi * r
    segments = []
    offset = 0
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        pct = n / total
        dash = circ * pct
        gap = circ - dash
        color = _SEVERITY_COLORS[sev]
        rotation = -90 + (offset / total) * 360
        segments.append(
            f'<circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="{color}" stroke-width="22"'
            f' stroke-dasharray="{dash:.1f} {gap:.1f}" transform="rotate({rotation:.1f} {center} {center})"'
            f' opacity="0.9"><title>{sev.capitalize()}: {n}</title></circle>'
        )
        offset += n
    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="Severity distribution">
  {"".join(segments)}
  <circle cx="{center}" cy="{center}" r="32" fill="#fff"/>
  <text x="{center}" y="{center - 4}" text-anchor="middle" font-size="20" font-weight="700" fill="#1a1a1a">{total}</text>
  <text x="{center}" y="{center + 12}" text-anchor="middle" font-size="8" fill="#666">PATHS</text>
</svg>"""


def _type_breakdown_svg(paths: list[dict]) -> str:
    """Horizontal bar chart of path types."""
    by_type: dict[str, list[dict]] = {}
    for p in paths:
        by_type.setdefault(p.get("Type", "unknown"), []).append(p)
    if not by_type:
        return ""
    sorted_types = sorted(by_type.items(), key=lambda x: -len(x[1]))[:8]
    max_count = max(len(g) for _, g in sorted_types) or 1
    bar_h = 22
    label_w = 110
    bar_w = 260
    gap = 6
    total_h = len(sorted_types) * (bar_h + gap) + 10
    svg_w = label_w + bar_w + 40

    bars = []
    for i, (ptype, group) in enumerate(sorted_types):
        y = i * (bar_h + gap) + 4
        w = (len(group) / max_count) * bar_w
        max_sev = min(group, key=lambda p: _SEVERITY_ORDER.get(p.get("Severity", "informational").lower(), 4))
        color = _SEVERITY_COLORS.get(max_sev.get("Severity", "informational").lower(), "#6B6B6B")
        label = _TYPE_LABELS.get(ptype, ptype)[:18]
        bars.append(
            f'<text x="{label_w - 6}" y="{y + bar_h // 2 + 4}" text-anchor="end"'
            f' font-size="10" fill="#555">{_esc(label)}</text>'
        )
        bars.append(
            f'<rect x="{label_w}" y="{y}" width="{w:.0f}" height="{bar_h}" rx="4"'
            f' fill="{color}" opacity="0.85"><title>{_esc(label)}: {len(group)}</title></rect>'
        )
        bars.append(
            f'<text x="{label_w + w + 6:.0f}" y="{y + bar_h // 2 + 4}"'
            f' font-size="11" font-weight="600" fill="#333">{len(group)}</text>'
        )
    return f'<svg width="{svg_w}" height="{total_h}" viewBox="0 0 {svg_w} {total_h}" style="max-width:100%">{"".join(bars)}</svg>'


def generate_executive_brief(assessment: dict) -> str:
    """Generate an enterprise-grade executive brief HTML."""
    summary = assessment.get("Summary", {})
    paths = assessment.get("Paths", [])
    tenant = assessment.get("TenantId", "unknown")
    ts = assessment.get("AssessmentTimestamp", "")[:19]
    score = summary.get("OverallRiskScore", 0)
    total = summary.get("TotalPaths", 0)
    counts = summary.get("SeverityCounts", {})
    by_type = summary.get("PathsByType", {})
    mitre_count = len(summary.get("MitreTechniques", []))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)

    # Posture
    if score >= 80:
        posture = "CRITICAL — Immediate remediation required. Active exploitation risk is high."
        posture_color = _SEVERITY_COLORS["critical"]
    elif score >= 60:
        posture = "HIGH — Significant attack paths require near-term action."
        posture_color = _SEVERITY_COLORS["high"]
    elif score >= 40:
        posture = "MODERATE — Targeted remediation of priority paths recommended."
        posture_color = _SEVERITY_COLORS["medium"]
    else:
        posture = "LOW — Attack surface well-managed. Continue monitoring."
        posture_color = "#107C10"

    # Remediation impact
    score_if_crit = max(0, score - crit * 8)
    score_if_all = max(0, score_if_crit - high * 4)

    # Top 5
    sorted_paths = sorted(paths, key=lambda p: -p.get("RiskScore", 0))[:5]
    top_rows = ""
    for i, p in enumerate(sorted_paths, 1):
        ps = p.get("Severity", "").lower()
        color = _SEVERITY_COLORS.get(ps, "#6B6B6B")
        chain = p.get("Chain", "")
        if len(chain) > 120:
            chain = chain[:117] + "…"
        mitre_t = p.get("MitreTechnique", "")
        mitre_badge = f' <span style="background:#e8f0fe;color:#0078d4;padding:1px 5px;border-radius:3px;font-size:.7rem;font-family:monospace">{_esc(mitre_t)}</span>' if mitre_t else ""
        top_rows += f"""<tr>
  <td style="text-align:center;font-weight:700;width:30px">{i}</td>
  <td style="width:70px"><span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:600">{_esc(ps.upper())}</span></td>
  <td style="text-align:center;font-weight:700;width:45px;color:{color}">{p.get('RiskScore', 0)}</td>
  <td style="font-size:.82rem;line-height:1.4">{_esc(chain)}{mitre_badge}</td>
</tr>"""

    # Recommendations
    seen: set[str] = set()
    recs = []
    for p in sorted_paths:
        r = p.get("Remediation", "")
        if r and r not in seen:
            seen.add(r)
            recs.append((r, p.get("MSLearnUrl", "")))
    rec_items = ""
    for r, url in recs[:5]:
        link = f' <a href="{_esc(url)}" target="_blank" style="color:#0078d4;text-decoration:none">[Learn&nbsp;more]</a>' if url else ""
        rec_items += f"<li>{_esc(r)}{link}</li>"

    # Trend
    trend_html = ""
    trend = summary.get("Trend")
    if trend:
        d = trend.get("Direction", "stable")
        if d == "improved":
            arrow, tcolor = "↓", "#107C10"
        elif d == "worsened":
            arrow, tcolor = "↑", "#D13438"
        else:
            arrow, tcolor = "→", "#FFB900"
        trend_html = f"""<div class="trend-box">
  <span style="color:{tcolor};font-weight:700;font-size:1.2rem">{arrow}</span>
  <span><strong>{d.capitalize()}</strong> — +{trend.get('NewPaths',0)} new, -{trend.get('ResolvedPaths',0)} resolved</span>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Path — Executive Brief — {_esc(tenant)}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;margin:0;padding:0;color:#1a1a1a;background:#fff;font-size:13px;line-height:1.5}}
.page{{max-width:920px;margin:0 auto;padding:28px 36px}}
.header{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;padding-bottom:16px;border-bottom:3px solid #0078D4}}
.header h1{{font-size:1.3rem;margin:0 0 2px;color:#1a1a1a}}
.header .subtitle{{color:#555;font-size:.82rem}}
.classification{{display:inline-block;padding:2px 10px;background:#d134381a;color:#D13438;border-radius:4px;font-size:.7rem;font-weight:600;letter-spacing:.5px;text-transform:uppercase}}
.posture{{padding:14px 18px;border-radius:8px;margin-bottom:20px;font-size:.95rem;font-weight:600;border-left:5px solid}}
.dashboard{{display:flex;gap:20px;margin-bottom:20px;align-items:flex-start}}
.viz-col{{display:flex;gap:16px;align-items:center}}
.legend{{display:flex;flex-direction:column;gap:3px;font-size:.75rem}}
.legend-item{{display:flex;align-items:center;gap:5px}}
.legend-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;flex:1}}
.kpi{{text-align:center;padding:10px;border:1px solid #e8e8e8;border-radius:8px;background:#fafafa}}
.kpi-val{{font-size:1.5rem;font-weight:700}}
.kpi-lbl{{font-size:.7rem;color:#666;text-transform:uppercase;letter-spacing:.4px}}
.section-title{{font-size:1rem;margin:22px 0 10px;padding-bottom:5px;border-bottom:2px solid #e0e0e0;color:#333}}
.impact-row{{display:flex;gap:12px;margin-bottom:18px}}
.impact-card{{flex:1;text-align:center;padding:10px;border:1px solid #e8e8e8;border-radius:8px}}
.impact-card .val{{font-size:1.4rem;font-weight:700}}
.impact-card .lbl{{font-size:.7rem;color:#666}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:7px 8px;text-align:left;border-bottom:1px solid #e8e8e8}}
th{{background:#f7f7f7;font-size:.78rem;color:#555;text-transform:uppercase;letter-spacing:.3px}}
ol{{padding-left:18px;margin:0}}
li{{margin:5px 0;font-size:.85rem;line-height:1.5}}
.trend-box{{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#f0f9ff;border:1px solid #d0e8ff;border-radius:6px;font-size:.85rem;margin-bottom:16px}}
.breakdown-section{{margin-top:16px}}
.footer{{margin-top:24px;padding-top:12px;border-top:1px solid #e0e0e0;text-align:center;color:#999;font-size:.7rem}}
@media print{{
  body{{font-size:11px}}
  .page{{padding:12px;max-width:100%}}
  .kpi-grid{{grid-template-columns:repeat(4,1fr)}}
  .dashboard{{gap:12px}}
  svg{{max-width:100%!important}}
  @page{{margin:12mm;size:A4 portrait}}
}}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <h1>🛡️ Attack Path Detection — Executive Brief</h1>
      <div class="subtitle">Tenant: <code>{_esc(tenant)}</code> &mdash; {_esc(ts or now)}</div>
    </div>
    <div class="classification">CONFIDENTIAL</div>
  </div>

  <div class="posture" style="background:{posture_color}10;border-color:{posture_color};color:{posture_color}">
    {_esc(posture)}
  </div>

  {trend_html}

  <div class="dashboard">
    <div class="viz-col">
      {_ring_gauge_svg(score)}
      {_donut_svg(counts)}
      <div class="legend">
        {"".join(f'<span class="legend-item"><span class="legend-dot" style="background:{_SEVERITY_COLORS[s]}"></span>{s.capitalize()}: {counts.get(s,0)}</span>' for s in ("critical","high","medium","low","informational") if counts.get(s,0))}
      </div>
    </div>
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-val">{total}</div><div class="kpi-lbl">Total Paths</div></div>
      <div class="kpi"><div class="kpi-val" style="color:{_SEVERITY_COLORS['critical']}">{crit}</div><div class="kpi-lbl">Critical</div></div>
      <div class="kpi"><div class="kpi-val" style="color:{_SEVERITY_COLORS['high']}">{high}</div><div class="kpi-lbl">High</div></div>
      <div class="kpi"><div class="kpi-val" style="color:{_SEVERITY_COLORS['medium']}">{med}</div><div class="kpi-lbl">Medium</div></div>
      <div class="kpi"><div class="kpi-val" style="color:{_SEVERITY_COLORS['low']}">{low}</div><div class="kpi-lbl">Low</div></div>
      <div class="kpi"><div class="kpi-val">{mitre_count}</div><div class="kpi-lbl">MITRE Techniques</div></div>
      <div class="kpi"><div class="kpi-val">{len(by_type)}</div><div class="kpi-lbl">Categories</div></div>
      <div class="kpi"><div class="kpi-val" style="color:{_SEVERITY_COLORS['critical']}">{crit + high}</div><div class="kpi-lbl">Action Required</div></div>
    </div>
  </div>

  <h2 class="section-title">Remediation Impact Projection</h2>
  <div class="impact-row">
    <div class="impact-card"><div class="val" style="color:{_SEVERITY_COLORS['critical']}">{score}</div><div class="lbl">Current Score</div></div>
    <div class="impact-card"><div class="val" style="color:{_SEVERITY_COLORS['high']}">{score_if_crit}</div><div class="lbl">If {crit} Critical Fixed</div></div>
    <div class="impact-card"><div class="val" style="color:#107C10">{score_if_all}</div><div class="lbl">If Critical + {high} High Fixed</div></div>
  </div>

  <div class="breakdown-section">
    <h2 class="section-title">Attack Path Categories</h2>
    {_type_breakdown_svg(paths)}
  </div>

  <h2 class="section-title">Top 5 Attack Paths</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Description</th></tr></thead>
    <tbody>{top_rows if top_rows else '<tr><td colspan="4" style="text-align:center;color:#999">No attack paths detected</td></tr>'}</tbody>
  </table>

  <h2 class="section-title">Key Recommendations</h2>
  <ol>{rec_items if rec_items else '<li>No high-priority recommendations at this time.</li>'}</ol>

  <div class="footer">
    EnterpriseSecurityIQ — Attack Path Detection &copy; {datetime.now().year} &mdash; Generated {_esc(now)} &mdash; CONFIDENTIAL
  </div>
</div>
</body>
</html>"""
