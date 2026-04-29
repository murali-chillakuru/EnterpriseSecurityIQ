"""Convert Technical-Docs Markdown files to themed HTML.

Run from the repository root:
    python Technical-Docs/build_html.py
"""

import re, html, pathlib, textwrap

DOCS_DIR = pathlib.Path(__file__).resolve().parent
NAV_ITEMS = [
    ("index-of-tech-docs.html",                       "Home"),
    ("01-infrastructure-overview.html",  "Infrastructure"),
    ("02-assessment-guide.html",         "Assessments"),
    ("03-report-lifecycle.html",         "Reports"),
    ("04-manual-setup-guide.html",       "Setup"),
    ("05-authentication-flow.html",      "Auth"),
    ("06-api-reference.html",            "API"),
    ("07-teams-integration.html",        "Teams"),
    ("08-troubleshooting.html",          "Troubleshoot"),
]

HTML_TEMPLATE = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — PostureIQ Technical Docs</title>
  <link rel="stylesheet" href="../docs/theme.css">
  <link rel="stylesheet" href="../docs/print.css">
  <script src="../docs/theme.js"></script>
</head>
<body>

<header class="doc-header">
  <a href="index-of-tech-docs.html" class="doc-header-brand">
    <svg viewBox="0 0 28 28" fill="none"><rect width="28" height="28" rx="6" fill="var(--bg-accent)"/><path d="M8 8h4v12H8V8zm8 4h4v8h-4v-8z" fill="var(--text-on-accent)"/></svg>
    <span>PostureIQ Technical Docs</span>
  </a>
  <nav class="doc-header-nav">
{nav_links}
    <button class="theme-toggle" aria-label="Toggle theme"></button>
  </nav>
</header>

<main class="doc-container">
{body}
</main>

</body>
</html>
""")


def _nav_links(active_file: str) -> str:
    lines = []
    for href, label in NAV_ITEMS:
        cls = ' class="active"' if href == active_file else ""
        lines.append(f'    <a href="{href}"{cls}>{label}</a>')
    return "\n".join(lines)


# ── Markdown → HTML (minimal, covers what the docs use) ──────────

def _md_to_html(md: str) -> str:
    """Convert a subset of Markdown to HTML (tables, headings, code, lists, paragraphs)."""
    lines = md.split("\n")
    out: list[str] = []
    i = 0

    def _inline(t: str) -> str:
        # bold
        t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
        # italic
        t = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<em>\1</em>', t)
        # inline code
        t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
        # links  [text](url)
        t = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', t)
        return t

    while i < len(lines):
        line = lines[i]

        # fenced code block
        m = re.match(r'^```(\w*)', line)
        if m:
            lang = m.group(1)
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(html.escape(lines[i]))
                i += 1
            i += 1  # skip closing ```
            cls = f' class="language-{lang}"' if lang else ""
            out.append(f'<pre><code{cls}>{chr(10).join(code_lines)}</code></pre>')
            continue

        # heading
        m = re.match(r'^(#{1,6})\s+(.*)', line)
        if m:
            lvl = len(m.group(1))
            text = _inline(m.group(2))
            slug = re.sub(r'[^a-z0-9]+', '-', m.group(2).lower()).strip('-')
            out.append(f'<h{lvl} id="{slug}">{text}</h{lvl}>')
            i += 1
            continue

        # horizontal rule
        if re.match(r'^---+\s*$', line):
            out.append("<hr>")
            i += 1
            continue

        # blockquote
        if line.startswith("> "):
            bq_lines = []
            while i < len(lines) and lines[i].startswith("> "):
                bq_lines.append(_inline(lines[i][2:]))
                i += 1
            out.append(f'<blockquote><p>{"<br>".join(bq_lines)}</p></blockquote>')
            continue

        # table
        if "|" in line and i + 1 < len(lines) and re.match(r'^\|[\s:|-]+\|', lines[i + 1]):
            headers = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2  # skip header + separator
            rows = []
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells)
                i += 1
            tbl = '<table>\n<thead><tr>'
            for h in headers:
                tbl += f'<th>{_inline(h)}</th>'
            tbl += '</tr></thead>\n<tbody>\n'
            for row in rows:
                tbl += '<tr>'
                for c in row:
                    tbl += f'<td>{_inline(c)}</td>'
                tbl += '</tr>\n'
            tbl += '</tbody></table>'
            out.append(tbl)
            continue

        # unordered list
        if re.match(r'^[-*]\s', line):
            items = []
            while i < len(lines) and re.match(r'^[-*]\s', lines[i]):
                items.append(_inline(lines[i][2:]))
                i += 1
            out.append('<ul>\n' + ''.join(f'<li>{it}</li>\n' for it in items) + '</ul>')
            continue

        # ordered list
        if re.match(r'^\d+\.\s', line):
            items = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i]):
                items.append(_inline(re.sub(r'^\d+\.\s', '', lines[i])))
                i += 1
            out.append('<ol>\n' + ''.join(f'<li>{it}</li>\n' for it in items) + '</ol>')
            continue

        # blank line
        if not line.strip():
            i += 1
            continue

        # paragraph
        para = []
        while i < len(lines) and lines[i].strip() and not re.match(r'^(#{1,6}\s|```|[-*]\s|\d+\.\s|>\s|\|.*\||---)', lines[i]):
            para.append(_inline(lines[i]))
            i += 1
        if para:
            out.append(f'<p>{"<br>\n".join(para)}</p>')
        else:
            i += 1

    return "\n".join(out)


def convert_file(md_path: pathlib.Path) -> None:
    md_text = md_path.read_text(encoding="utf-8")

    # Extract title from first heading
    m = re.search(r'^#\s+(.+)', md_text, re.MULTILINE)
    title = m.group(1) if m else md_path.stem

    # Convert .md links to .html links
    md_text = re.sub(r'\]\((\d\d-[^)]+)\.md', r'](\1.html', md_text)
    md_text = re.sub(r'\]\(index\.md', r'](index-of-tech-docs.html', md_text)

    html_name = md_path.stem + ".html"
    body = _md_to_html(md_text)
    nav = _nav_links(html_name)
    result = HTML_TEMPLATE.format(title=html.escape(title), nav_links=nav, body=body)

    out_path = md_path.with_suffix(".html")
    out_path.write_text(result, encoding="utf-8")
    print(f"  Created {out_path.name}")


def main():
    md_files = sorted(DOCS_DIR.glob("*.md"))
    print(f"Converting {len(md_files)} Markdown files to HTML...")
    for md in md_files:
        convert_file(md)
    print("Done.")


if __name__ == "__main__":
    main()
