"""Disclosure of scan settings that reduce findings, shared by every report.

The lines come from the scanned checkout's configuration, so all text is escaped.
"""

import sys

from rich.markup import escape

from tf_eu_guard.reporting.html_common import esc

HEADING = "Scan settings that reduce findings"


def weakening_html(lines: list[str] | None) -> str:
    """Render the settings as an HTML block ('' when none)."""
    if not lines:
        return ""
    items = "".join(f"<li><code>{esc(line)}</code></li>" for line in lines)
    return f'<div class="scope"><strong>{HEADING}</strong><ul>{items}</ul></div>\n'


def weakening_rich(lines: list[str] | None) -> list[str]:
    """Rich-markup lines for the terminal report ([] when none)."""
    if not lines:
        return []
    return [f"[yellow]{HEADING}:[/yellow]", *(f"  - {escape(line)}" for line in lines), ""]


def print_weakening_to_stderr(settings: list[str]) -> None:
    """Plain-text disclosure for machine-readable stdout formats (nothing when empty)."""
    if settings:
        print(f"{HEADING}:", file=sys.stderr)
        for line in settings:
            print(f"  {line}", file=sys.stderr)
