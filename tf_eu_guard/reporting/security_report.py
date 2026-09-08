"""Security report — a self-contained HTML dashboard grouped by severity.

Produces a single ``.html`` file (embedded CSS, no JavaScript, no external
assets) intended for security engineers triaging a scan: summary stats, a
finding-distribution bar chart, and severity-grouped finding cards.

The HTML is built with the standard library (:mod:`html` for escaping) rather
than a template engine so the output stays a single dependency-free file and the
generator has no packaging/template-loading surface. See ``PROJECT_PLAN.md`` §4.2.
"""

from pathlib import Path

from tf_eu_guard.models import EnrichedFinding, Framework
from tf_eu_guard.reporting._html_common import (
    distinct_files,
    esc,
    finding_card,
    severity_counts,
)
from tf_eu_guard.reporting.styles import SECURITY_CSS, SEVERITY_COLOR, SEVERITY_ORDER


def _summary_stats(
    findings: list[EnrichedFinding], unmapped_count: int = 0
) -> str:
    """Render the top-of-page summary stat cards."""
    counts = severity_counts(findings)
    nis2 = sum(1 for f in findings if Framework.NIS2 in f.frameworks)
    gdpr = sum(1 for f in findings if Framework.GDPR in f.frameworks)

    cards: list[str] = [
        f'<div class="stat"><div class="num">{len(findings)}</div>'
        f'<div class="label">Findings</div></div>',
        f'<div class="stat"><div class="num">{distinct_files(findings)}</div>'
        f'<div class="label">Files</div></div>',
    ]
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            cards.append(
                f'<div class="stat"><div class="num" style="color:{SEVERITY_COLOR[sev]}">'
                f'{counts[sev]}</div><div class="label">{esc(sev.value)}</div></div>'
            )
    if unmapped_count:
        cards.append(
            f'<div class="stat"><div class="num" style="color:#7f8c8d">{unmapped_count}</div>'
            f'<div class="label">Unmapped</div></div>'
        )
    cards.append(
        f'<div class="stat"><div class="num">{nis2}</div><div class="label">NIS2</div></div>'
    )
    cards.append(
        f'<div class="stat"><div class="num">{gdpr}</div><div class="label">GDPR</div></div>'
    )
    return '<section class="summary">\n' + "\n".join(cards) + "\n</section>"


def _distribution_chart(findings: list[EnrichedFinding]) -> str:
    """Render a CSS-only bar chart of the severity distribution."""
    counts = severity_counts(findings)
    present = [s for s in SEVERITY_ORDER if counts[s]]
    if not present:
        return ""
    max_count = max(counts[s] for s in present)
    rows: list[str] = []
    for sev in present:
        n = counts[sev]
        width = max(2, round(n / max_count * 100))
        rows.append(
            '<div class="row">'
            f'<span class="rlabel">{esc(sev.value)}</span>'
            '<span class="track">'
            f'<span class="bar" style="width:{width}%;background:{SEVERITY_COLOR[sev]}"></span>'
            "</span>"
            f'<span class="rcount">{n}</span>'
            "</div>"
        )
    return (
        '<h2>Finding distribution</h2>\n<section class="chart">\n'
        + "\n".join(rows)
        + "\n</section>"
    )


def _render(
    findings: list[EnrichedFinding],
    *,
    target: str,
    timestamp: str,
    version: str,
    unmapped_count: int = 0,
) -> str:
    """Assemble the complete HTML document."""
    unmapped_span = (
        f"<span>Unmapped Checkov findings: {unmapped_count}</span>"
        if unmapped_count
        else ""
    )
    header = (
        "<header>\n"
        "  <h1>tf-eu-guard &mdash; Security Report</h1>\n"
        '  <div class="meta">'
        f'<span>Target: <code>{esc(target) or "&mdash;"}</code></span>'
        f"<span>Generated: {esc(timestamp) or '&mdash;'}</span>"
        f"<span>Findings: {len(findings)}</span>"
        f"{unmapped_span}"
        "</div>\n"
        "</header>"
    )

    if not findings and not unmapped_count:
        body = (
            '<div class="empty"><h2 style="margin-top:0">No compliance findings</h2>'
            "<p>Checkov reported no failed checks that map to a NIS2 or GDPR control "
            "for this target.</p></div>"
        )
    elif not findings:
        body = (
            '<div class="empty"><h2 style="margin-top:0">No mapped compliance findings'
            f" &mdash; {unmapped_count} unmapped</h2>"
            "<p>Checkov reported no failed checks that map to a NIS2 or GDPR control, "
            f"but <strong>{unmapped_count}</strong> failed check(s) have no current EU "
            "regulatory mapping and are not shown here. This scan is not a clean bill "
            "of health &mdash; review them with a plain Checkov run.</p></div>"
        )
    else:
        sections = [_summary_stats(findings, unmapped_count), _distribution_chart(findings)]
        if unmapped_count:
            sections.append(
                f'<p class="unmapped"><strong>{unmapped_count}</strong> additional '
                "Checkov finding(s) have no current EU regulatory mapping and are not "
                "shown in this report.</p>"
            )
        # Group findings by severity (CRITICAL -> INFO); sort within by file then check id.
        by_sev: dict = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
            by_sev.setdefault(f.severity, []).append(f)
        detail = ["<h2>Findings by severity</h2>"]
        for sev in SEVERITY_ORDER:
            group = by_sev.get(sev) or []
            if not group:
                continue
            group.sort(key=lambda f: (f.file_path, f.check_id))
            detail.append(
                f'<h3 style="color:{SEVERITY_COLOR[sev]}">{esc(sev.value)} '
                f"({len(group)})</h3>"
            )
            detail.extend(finding_card(f) for f in group)
        body = "\n".join(sections + detail)

    footer = (
        "<footer>Generated by tf-eu-guard"
        f"{' v' + esc(version) if version else ''}"
        f"{' on ' + esc(timestamp) if timestamp else ''}. "
        "Only failed checks that map to a NIS2/GDPR control are shown; "
        f"{unmapped_count} unmapped Checkov finding(s) "
        "were reported separately; "
        "absence of a finding is not evidence of compliance.</footer>"
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>tf-eu-guard Security Report</title>\n"
        f"<style>{SECURITY_CSS}</style>\n"
        "</head>\n<body>\n"
        f"{header}\n{body}\n{footer}\n"
        "</body>\n</html>\n"
    )


def generate_security_report(
    findings: list[EnrichedFinding],
    *,
    target: str = "",
    timestamp: str = "",
    version: str = "",
    output_path: Path | None = None,
    unmapped_count: int = 0,
) -> str:
    """Generate the self-contained HTML security dashboard.

    Args:
        findings: Enriched findings (as produced by ``enrich_findings``).
        target: Human-readable scan target (shown in the header).
        timestamp: Human-readable scan time (shown in the header/footer).
        version: tf-eu-guard version (shown in the footer).
        output_path: If given, the HTML is also written to this path (UTF-8).
        unmapped_count: Checkov findings with no registry mapping — shown as a
            count so they are present-but-unmapped, not absent.

    Returns:
        The complete HTML document as a string.
    """
    document = _render(
        findings,
        target=target,
        timestamp=timestamp,
        version=version,
        unmapped_count=unmapped_count,
    )
    if output_path is not None:
        Path(output_path).write_text(document, encoding="utf-8")
    return document
