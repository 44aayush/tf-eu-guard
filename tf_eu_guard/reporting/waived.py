"""Presentation of findings accepted by the reviewed waiver file.

Waived findings stay visible in every report: waiver owner and reason come from
the scanned checkout, so all text is escaped here.
"""

from rich.markup import escape

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.html_common import esc
from tf_eu_guard.reporting.sorting import sort_findings
from tf_eu_guard.reporting.untrusted import sanitize

_NOTE = (
    "These findings are covered by a reviewed waiver and do not affect "
    "--fail-on-severity, --fail-on-any or --fail-on-suppressed. Anyone who can edit "
    "the waiver file can add one, so review each entry and its expiry."
)


def _location(f: EnrichedFinding) -> str:
    lines = f.file_line_range or []
    return (
        f"{f.file_path}:{lines[0]}-{lines[1]}"
        if len(lines) >= 2 and any(lines[:2])
        else f.file_path
    )


def waived_html(waived: list[EnrichedFinding]) -> str:
    """Render the HTML table of waived findings ('' when none)."""
    rows = "\n".join(
        "<tr>"
        f"<td><code>{esc(f.check_id)}</code><br>{esc(f.check_name)}</td>"
        f"<td><code>{esc(f.resource)}</code></td>"
        f"<td><code>{esc(_location(f))}</code></td>"
        f"<td>{esc(f.waiver.owner)}</td><td>{esc(f.waiver.reason)}</td>"
        f"<td>{esc(f.waiver.expires.isoformat())}</td>"
        "</tr>"
        for f in sort_findings(waived)
        if f.waiver
    )
    if not rows:
        return ""
    return (
        '<section class="suppressed waived">\n'
        f"<h2>Waived by reviewed waiver file ({len(waived)})</h2>\n<p>{esc(_NOTE)}</p>\n"
        '<table class="suppressed-table">\n'
        "<thead><tr><th>Check</th><th>Resource</th><th>Location</th>"
        "<th>Owner</th><th>Reason</th><th>Expires</th></tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n</table>\n</section>"
    )


def waived_lines(waived: list[EnrichedFinding]) -> list[str]:
    """Rich-markup lines for the dev terminal 'Waived' section."""
    lines = [
        f"\n[bold yellow]Waived by reviewed waiver file ({len(waived)})[/bold yellow]",
        f"[dim]{escape(_NOTE)}[/dim]",
    ]
    for f in sort_findings(waived):
        if not f.waiver:
            continue
        lines.append(
            f"\n  [yellow]○[/yellow] [bold]{escape(sanitize(f.check_id))}[/bold]: {escape(sanitize(f.check_name))}"
        )
        lines.append(f"    [dim]Resource:[/dim] {escape(sanitize(f.resource))}")
        lines.append(f"    [dim]File:[/dim] {escape(sanitize(_location(f)))}")
        lines.append(f"    [dim]Owner:[/dim] {escape(sanitize(f.waiver.owner))}")
        lines.append(f"    [dim]Reason:[/dim] {escape(sanitize(f.waiver.reason))}")
        lines.append(f"    [dim]Expires:[/dim] {escape(f.waiver.expires.isoformat())}")
    return lines
