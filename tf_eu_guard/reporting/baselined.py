"""Presentation of findings already known from the ``--baseline`` report.

Known findings stay visible in every report but do not trip the gate. The text
comes from the scanned checkout, so it is escaped here.
"""

from rich.markup import escape

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.html_common import esc
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
