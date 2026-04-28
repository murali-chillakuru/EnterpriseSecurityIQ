"""PDF export via Playwright Chromium — renders HTML to PDF."""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


async def html_to_pdf(html_path: str | Path, pdf_path: str | Path) -> Path:
    """Convert an HTML file to PDF using Playwright."""
    from playwright.async_api import async_playwright

    html_path = Path(html_path)
    pdf_path = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        await page.goto(html_path.as_uri())
        await page.pdf(
            path=str(pdf_path),
            format="A4",
            margin={"top": "20mm", "bottom": "20mm", "left": "15mm", "right": "15mm"},
            print_background=True,
        )
        await browser.close()

    log.info("PDF generated: %s", pdf_path)
    return pdf_path
