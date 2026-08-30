"""Render a captured ANSI terminal capture to an SVG (via rich) and a PNG (via Playwright).

Usage: venv/bin/python tools/ansi_to_image.py <input.ansi> <output.png> [title]
"""
import io
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    title = sys.argv[3] if len(sys.argv) > 3 else "tf-eu-guard"
    ansi = src.read_text()
    if len(sys.argv) > 4:
        ansi = "\n".join(ansi.splitlines()[: int(sys.argv[4])])
    buffer = io.StringIO()
    console = Console(
        file=buffer, record=True, width=110, force_terminal=True, color_system="truecolor"
    )
    console.print(Text.from_ansi(ansi))
    svg_path = dst.with_suffix(".svg")
    svg_path.write_text(console.export_svg(title=title))

    from playwright.sync_api import sync_playwright

    html_path = dst.with_suffix(".html")
    html_path.write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>body{margin:0;background:#0d1117}</style></head><body>"
        f"<img src='{svg_path.name}'></body></html>"
    )
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1180, "height": 800}, device_scale_factor=2)
        page.goto(html_path.resolve().as_uri())
        page.wait_for_timeout(500)
        page.screenshot(path=str(dst), full_page=True)
        browser.close()
    html_path.unlink()
    print(f"wrote {dst} (+ {svg_path})")


if __name__ == "__main__":
    main()
