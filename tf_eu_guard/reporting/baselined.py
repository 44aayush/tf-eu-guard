"""Presentation of findings already known from the ``--baseline`` report.

Known findings stay visible in every report but do not trip the gate. The text
comes from the scanned checkout, so it is escaped here.
"""

from typing import Any

from rich.markup import escape

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.html_common import esc, unmapped_rows
from tf_eu_guard.reporting.sorting import sort_findings
from tf_eu_guard.reporting.untrusted import sanitize
from tf_eu_guard.reporting.waived import _location

TITLE = "Known (in baseline)"
_NOTE = (
    "These findings were already present in the --baseline report. They do not affect "
    "--fail-on-severity or --fail-on-any, but they are still open."
)


def baselined_html(baselined: list[EnrichedFinding]) -> str:
    """Render the HTML table of known findings ('' when none)."""
    if not baselined:
        return ""
    rows = "\n".join(
        "<tr>"
        f"<td><code>{esc(f.check_id)}</code><br>{esc(f.check_name)}</td>"
        f"<td>{esc(f.severity.value)}</td>"
        f"<td><code>{esc(f.resource)}</code></td>"
        f"<td><code>{esc(_location(f))}</code></td>"
        "</tr>"
        for f in sort_findings(baselined)
    )
    return (
        '<section class="suppressed baselined">\n'
        f"<h2>{TITLE} ({len(baselined)})</h2>\n<p>{esc(_NOTE)}</p>\n"
        '<table class="suppressed-table">\n'
        "<thead><tr><th>Check</th><th>Severity</th><th>Resource</th><th>Location</th></tr>"
        f"</thead>\n<tbody>\n{rows}\n</tbody>\n</table>\n</section>"
    )


def baselined_lines(baselined: list[EnrichedFinding]) -> list[str]:
    """Rich-markup lines for the dev terminal 'Known' section."""
    lines = [
        f"\n[bold yellow]{TITLE} ({len(baselined)})[/bold yellow]",
        f"[dim]{escape(_NOTE)}[/dim]",
    ]
    for f in sort_findings(baselined):
        lines.append(
            f"\n  [yellow]○[/yellow] [bold]{escape(sanitize(f.check_id))}[/bold]: {escape(sanitize(f.check_name))}"
        )
        lines.append(f"    [dim]Resource:[/dim] {escape(sanitize(f.resource))}")
        lines.append(f"    [dim]File:[/dim] {escape(sanitize(_location(f)))}")
        lines.append(f"    [dim]Severity:[/dim] {escape(f.severity.value)}")
    return lines


UNMAPPED_TITLE = "Known unmapped (in baseline)"


def baselined_unmapped_html(entries: list[dict[str, Any]], listed: bool = False) -> str:
    """HTML section for known unmapped findings: the count, plus rows when ``listed``."""
    if not entries:
        return ""
    table = ""
    if listed:
        rows = "\n".join(
            f"<tr><td><code>{esc(cid)}</code></td><td>{esc(name)}</td><td>{esc(res)}</td>"
            f"<td>{esc(path)}</td><td>{esc(lines)}</td></tr>"
            for cid, name, res, path, lines in unmapped_rows(entries)
        )
        table = (
            '<table class="suppressed-table">\n<thead><tr><th>Check</th><th>Name</th>'
            "<th>Resource</th><th>File</th><th>Lines</th></tr></thead>\n"
            f"<tbody>\n{rows}\n</tbody>\n</table>\n"
        )
    return (
        '<section class="suppressed baselined">\n'
        f"<h2>{UNMAPPED_TITLE} ({len(entries)})</h2>\n<p>{esc(_NOTE)}</p>\n{table}</section>"
    )


def baselined_unmapped_lines(entries: list[dict[str, Any]], listed: bool = False) -> list[str]:
    """Rich-markup lines for known unmapped findings (rows only when ``listed``)."""
    if not entries:
        return []
    lines = [
        f"\n[bold yellow]{UNMAPPED_TITLE} ({len(entries)})[/bold yellow]",
        f"[dim]{escape(_NOTE)}[/dim]",
    ]
    if listed:
        for cid, name, res, path, span in unmapped_rows(entries):
            lines.append(
                f"  [dim]- {escape(sanitize(cid))} {escape(sanitize(name))} | "
                f"{escape(sanitize(res))} | {escape(sanitize(path))}:{escape(sanitize(span))}[/dim]"
            )
    return lines
