"""Re-render attack-path HTML from an existing JSON assessment (no re-collection)."""
import json
import sys
from pathlib import Path

from app.attackpath_reports.attack_path_report import generate_html_report

if len(sys.argv) < 2:
    print("Usage: python _render_attack_html.py <path-to-attack-path-assessment.json>")
    sys.exit(1)

src = Path(sys.argv[1]).resolve()
assessment = json.loads(src.read_text(encoding="utf-8"))
html = generate_html_report(assessment)
out = src.parent / "attack-path-report.html"
out.write_text(html, encoding="utf-8")
print(f"Rendered {len(html):,} chars -> {out}")
