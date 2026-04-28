"""Shared HTML theme — Fluent 2 inspired CSS + JS for all reports."""

from __future__ import annotations

THEME_CSS = """
:root {
    --bg-primary:    #ffffff;
    --bg-secondary:  #f5f5f5;
    --bg-card:       #ffffff;
    --text-primary:  #242424;
    --text-secondary:#616161;
    --accent:        #0078d4;
    --border:        #e0e0e0;
    --success:       #107c10;
    --warning:       #ffb900;
    --error:         #d13438;
    --critical:      #a4262c;
    --font:          'Segoe UI', -apple-system, sans-serif;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg-primary:    #1b1b1b;
        --bg-secondary:  #2d2d2d;
        --bg-card:       #292929;
        --text-primary:  #ffffff;
        --text-secondary:#d2d2d2;
        --border:        #404040;
    }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg-primary); color: var(--text-primary); line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.card h2 { font-size: 18px; margin-bottom: 12px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-critical { background: var(--critical); color: #fff; }
.badge-high { background: var(--error); color: #fff; }
.badge-medium { background: var(--warning); color: #000; }
.badge-low { background: var(--success); color: #fff; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }
th { background: var(--bg-secondary); font-weight: 600; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.score-ring { width: 120px; height: 120px; }
"""

THEME_JS = """
function initTheme() {
    // Auto dark/light from system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}
document.addEventListener('DOMContentLoaded', initTheme);
"""


def wrap_html(title: str, body: str, extra_css: str = "", extra_js: str = "") -> str:
    """Wrap body content in a complete self-contained HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{THEME_CSS}{extra_css}</style>
</head>
<body>
<div class="container">
{body}
</div>
<script>{THEME_JS}{extra_js}</script>
</body>
</html>"""
