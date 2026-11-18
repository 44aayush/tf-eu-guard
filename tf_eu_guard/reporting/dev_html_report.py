"""Developer HTML report — the ``dev`` findings view as a shareable HTML file.

Carries the same information as the terminal ``dev`` report but rendered as a
single self-contained HTML file (embedded CSS, no JavaScript, no external
assets) so it can be attached to a pull request or shared without a terminal.

Where the *security* report groups by severity for triage, this developer view
groups by **file** — the unit a developer actually edits — with findings inside
each file ordered most-severe first. The finding card itself is shared with the
    security report via :func:`tf_eu_guard.reporting.html_common.finding_card`.
"""

from pathlib import Path
from typing import Any

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.baselined import baselined_html
from tf_eu_guard.reporting.html_common import (
    distinct_files,
    esc,
    finding_card,
    severity_counts,
    unmapped_html,
)
from tf_eu_guard.reporting.sorting import finding_sort_key, sort_findings
from tf_eu_guard.reporting.styles import (
    CSP_META,
    DEV_HTML_CSS,
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    SUPPRESSED_CSS,
)
from tf_eu_guard.reporting.suppressed import SuppressedItem, suppressed_html, suppressed_items
from tf_eu_guard.reporting.waived import waived_html
from tf_eu_guard.reporting.weakening import weakening_html


def _severity_rank(finding: EnrichedFinding) -> int:
    """Sort key placing the most severe findings first (unknown severities last)."""
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return order.get(finding.severity, len(SEVERITY_ORDER))


def _summary_chips(findings: list[EnrichedFinding], unmapped_count: int = 0) -> str:
    """Render a compact one-line summary (totals + per-severity counts)."""
    counts = severity_counts(findings)
    chips: list[str] = [
        f'<span class="chip"><b>{len(findings)}</b> findings</span>',
        f'<span class="chip"><b>{distinct_files(findings)}</b> files</span>',
    ]
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            chips.append(
                f'<span class="chip" style="border-color:{SEVERITY_COLOR[sev]}">'
                f'<b style="color:{SEVERITY_COLOR[sev]}">{counts[sev]}</b> {esc(sev.value)}</span>'
            )
    if unmapped_count:
        chips.append(
            f'<span class="chip" style="border-color:#7f8c8d">'
            f'<b style="color:#7f8c8d">{unmapped_count}</b> unmapped</span>'
        )
    return '<section class="chips">\n' + "\n".join(chips) + "\n</section>"


def _file_section(file_path: str, group: list[EnrichedFinding]) -> str:
    """Render one file heading plus its findings (most severe first)."""
    group = sorted(group, key=lambda f: (_severity_rank(f), finding_sort_key(f)))
    n = len(group)
    heading = (
        '<div class="file-group">\n'
        f'<h2 class="file">{esc(file_path)}'
        f'<span class="fcount">{n} finding{"" if n == 1 else "s"}</span></h2>'
    )
    cards = "\n".join(finding_card(f) for f in group)
    return f"{heading}\n{cards}\n</div>"


def _render(
    findings: list[EnrichedFinding],
    *,
    target: str,
    timestamp: str,
    version: str,
    unmapped_count: int = 0,
    unmapped: list[dict[str, Any]] | None = None,
    suppressed: list[SuppressedItem] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
) -> str:
    """Assemble the complete HTML document."""
    findings = sort_findings(findings)
    suppressed = suppressed or []
    waived = waived or []
    baselined = baselined or []
    suppressed_span = f"<span>Suppressed: {len(suppressed)}</span>" if suppressed else ""
    suppressed_span += f"<span>Waived: {len(waived)}</span>" if waived else ""
    suppressed_span += f"<span>Known (in baseline): {len(baselined)}</span>" if baselined else ""
    unmapped_span = (
        f"<span>Unmapped Checkov findings: {unmapped_count}</span>" if unmapped_count else ""
    )
    header = (
        "<header>\n"
        "  <h1>tf-eu-guard &mdash; Developer Report</h1>\n"
        '  <div class="meta">'
        f"<span>Target: <code>{esc(target) or '&mdash;'}</code></span>"
        f"<span>Generated: {esc(timestamp) or '&mdash;'}</span>"
        f"<span>Findings: {len(findings)}</span>"
        f"{unmapped_span}{suppressed_span}"
        "</div>\n"
        f"{weakening_html(weakening_settings)}"
        "</header>"
    )

    if not findings and not unmapped_count and not suppressed and not waived and not baselined:
        body = (
            '<div class="empty"><h2 style="margin-top:0">No compliance findings</h2>'
            "<p>Checkov reported no failed checks that map to a compliance control "
            "for this target.</p></div>"
        )
    elif not findings and not unmapped_count:
        body = (
            '<div class="attention"><h2 style="margin-top:0">No active findings &mdash; '
            f"{len(suppressed)} suppressed, {len(waived)} waived, "
            f"{len(baselined)} known in baseline</h2>"
            "<p>Every failed check was suppressed by an inline comment or accepted by a "
            "waiver, or is already known from the baseline. This scan is not a clean bill of health &mdash; review the "
            "suppressed and waived checks below.</p></div>\n" + suppressed_html(suppressed)
        )
    elif not findings:
        body = (
            '<div class="empty"><h2 style="margin-top:0">No mapped compliance findings'
            f" &mdash; {unmapped_count} unmapped</h2>"
            "<p>Checkov reported no failed checks that map to a compliance control, "
            f"but <strong>{unmapped_count}</strong> failed check(s) have no current EU "
            "regulatory mapping and are not shown here. Review them with a plain "
            "Checkov run.</p></div>"
        )
    else:
        # Group by file; files sorted alphabetically for a stable, navigable layout.
        by_file: dict[str, list[EnrichedFinding]] = {}
        for f in findings:
            by_file.setdefault(f.file_path, []).append(f)
        sections = [
            _summary_chips(findings, unmapped_count),
            "<h2>Findings by file</h2>",
        ]
        if unmapped_count:
            sections.append(
                f'<p class="unmapped"><strong>{unmapped_count}</strong> additional '
                "Checkov finding(s) have no current EU regulatory mapping and are not "
                "shown in this report.</p>"
            )
        sections.extend(_file_section(path, by_file[path]) for path in sorted(by_file))
        body = "\n".join(sections)

    if unmapped:
        body = f"{body}\n{unmapped_html(unmapped)}"

    if suppressed and (findings or unmapped_count):
        body = f"{body}\n{suppressed_html(suppressed)}"

    if waived:
        body = f"{body}\n{waived_html(waived)}"

    if baselined:
        body = f"{body}\n{baselined_html(baselined)}"

    unmapped_note = (
        f"{unmapped_count} unmapped Checkov finding(s) were reported separately; "
        if unmapped_count
        else ""
    )
    footer = (
        "<footer>Generated by tf-eu-guard"
        f"{' v' + esc(version) if version else ''}"
        f"{' on ' + esc(timestamp) if timestamp else ''}. "
        "Only failed checks that map to a NIS2, GDPR, or project-policy control are shown; "
        f"{unmapped_note}"
        f"{len(suppressed)} finding(s) suppressed by inline comments, {len(waived)} "
        f"waived and {len(baselined)} known from the baseline are listed separately; "
        "this report is not legal advice and is not a certification; "
        "absence of a finding is not evidence of compliance.</footer>"
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"{CSP_META}\n"
        "<title>tf-eu-guard Developer Report</title>\n"
        f"<style>{DEV_HTML_CSS}{SUPPRESSED_CSS}</style>\n"
        "</head>\n<body>\n"
        f"{header}\n{body}\n{footer}\n"
        "</body>\n</html>\n"
    )


def generate_dev_html_report(
    findings: list[EnrichedFinding],
    *,
    target: str = "",
    timestamp: str = "",
    version: str = "",
    output_path: Path | None = None,
    unmapped_count: int = 0,
    unmapped: list[dict[str, Any]] | None = None,
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
) -> str:
    """Generate the self-contained developer HTML report (findings grouped by file).

    Args:
        findings: Enriched findings (as produced by ``enrich_findings``).
        target: Human-readable scan target (shown in the header).
        timestamp: Human-readable scan time (shown in the header/footer).
        version: tf-eu-guard version (shown in the footer).
        output_path: If given, the HTML is also written to this path (UTF-8).
        unmapped: Raw unmapped Checkov dicts; when given, listed in full
            (``--show-unmapped``).
        unmapped_count: Checkov findings with no registry mapping — shown as a
            count so they are present-but-unmapped, not absent.
        suppressed: Mapped findings suppressed by inline ``checkov:skip``
            comments — listed separately and never counted as active.
        suppressed_unmapped: Raw Checkov dicts for suppressed unmapped checks.

    Returns:
        The complete HTML document as a string.
    """
    document = _render(
        findings,
        target=target,
        timestamp=timestamp,
        version=version,
        unmapped_count=unmapped_count,
        unmapped=unmapped,
        suppressed=suppressed_items(suppressed, suppressed_unmapped),
        waived=waived,
        weakening_settings=weakening_settings,
        baselined=baselined,
    )
    if output_path is not None:
        Path(output_path).write_text(document, encoding="utf-8")
    return document
