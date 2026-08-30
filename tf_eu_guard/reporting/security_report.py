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
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    distinct_files,
    esc,
    finding_card,
    severity_counts,
)

_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    max-width: 1100px; margin: 40px auto; padding: 0 20px;
    color: #1a1a1a; background: #fafafa; line-height: 1.5;
  }
  header { border-bottom: 3px solid #2c3e50; padding-bottom: 16px; margin-bottom: 28px; }
  header h1 { margin: 0 0 6px; font-size: 1.7rem; }
  header .meta { color: #555; font-size: 0.9rem; }
  header .meta span { margin-right: 18px; white-space: nowrap; }
  h2 { font-size: 1.25rem; margin: 32px 0 12px; }

  .summary { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .stat {
    flex: 1 1 120px; background: #fff; border: 1px solid #e2e2e2; border-radius: 8px;
    padding: 14px 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }
  .stat .num { font-size: 1.7rem; font-weight: 700; line-height: 1; }
  .stat .label { font-size: 0.78rem; color: #666; text-transform: uppercase; letter-spacing: .04em; }

  .chart { background: #fff; border: 1px solid #e2e2e2; border-radius: 8px; padding: 18px 20px; }
  .chart .row { display: flex; align-items: center; gap: 12px; margin: 8px 0; }
  .chart .rlabel { flex: 0 0 90px; font-size: 0.85rem; font-weight: 600; }
  .chart .track { flex: 1; background: #eee; border-radius: 4px; overflow: hidden; }
  .chart .bar { height: 20px; border-radius: 4px 0 0 4px; min-width: 2px; }
  .chart .rcount { flex: 0 0 40px; text-align: right; font-variant-numeric: tabular-nums; }

  .finding {
    background: #fff; border: 1px solid #e2e2e2; border-left-width: 5px;
    border-radius: 6px; padding: 14px 18px; margin: 12px 0;
  }
  .finding-head { display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; }
  .finding-head .cid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; }
  .finding-head .cname { color: #333; }
  .badge {
    display: inline-block; color: #fff; font-size: 0.7rem; font-weight: 700;
    padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: .03em;
  }
  dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 10px 0; font-size: 0.9rem; }
  dl.meta dt { color: #777; font-weight: 600; }
  dl.meta dd { margin: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .art {
    display: inline-block; background: #eef2f7; border: 1px solid #d6e0ea; color: #2c3e50;
    font-size: 0.78rem; padding: 1px 7px; border-radius: 4px; margin: 1px 4px 1px 0;
  }
  .risk { margin: 8px 0; }
  .remediation h4 { margin: 10px 0 4px; font-size: 0.85rem; text-transform: uppercase; color: #777; letter-spacing: .04em; }
  .remediation pre {
    background: #f5f5f5; border: 1px solid #e2e2e2; border-radius: 6px;
    padding: 10px 12px; overflow-x: auto; margin: 0; font-size: 0.85rem;
  }
  .doc { display: inline-block; margin-top: 10px; font-size: 0.85rem; color: #2980b9; text-decoration: none; }
  .doc:hover { text-decoration: underline; }
  .empty { background: #eafaf1; border: 1px solid #abebc6; color: #1e6b43; padding: 24px; border-radius: 8px; text-align: center; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e2e2; color: #888; font-size: 0.82rem; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6e6e6; background: #16181c; }
    .stat, .chart, .finding { background: #21242b; border-color: #33373f; }
    .chart .track { background: #33373f; }
    dl.meta dt, .stat .label, header .meta { color: #aab; }
    .remediation pre { background: #1b1d22; border-color: #33373f; }
    .art { background: #2b3140; border-color: #3a4256; color: #cdd7e5; }
  }
"""


def _summary_stats(findings: list[EnrichedFinding]) -> str:
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
    findings: list[EnrichedFinding], *, target: str, timestamp: str, version: str
) -> str:
    """Assemble the complete HTML document."""
    header = (
        "<header>\n"
        "  <h1>tf-eu-guard &mdash; Security Report</h1>\n"
        '  <div class="meta">'
        f'<span>Target: <code>{esc(target) or "&mdash;"}</code></span>'
        f"<span>Generated: {esc(timestamp) or '&mdash;'}</span>"
        f"<span>Findings: {len(findings)}</span>"
        "</div>\n"
        "</header>"
    )

    if not findings:
        body = (
            '<div class="empty"><h2 style="margin-top:0">No compliance findings</h2>'
            "<p>Checkov reported no failed checks that map to a NIS2 or GDPR control "
            "for this target.</p></div>"
        )
    else:
        sections = [_summary_stats(findings), _distribution_chart(findings)]
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
        "absence of a finding is not evidence of compliance.</footer>"
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>tf-eu-guard Security Report</title>\n"
        f"<style>{_CSS}</style>\n"
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
) -> str:
    """Generate the self-contained HTML security dashboard.

    Args:
        findings: Enriched findings (as produced by ``enrich_findings``).
        target: Human-readable scan target (shown in the header).
        timestamp: Human-readable scan time (shown in the header/footer).
        version: tf-eu-guard version (shown in the footer).
        output_path: If given, the HTML is also written to this path (UTF-8).

    Returns:
        The complete HTML document as a string.
    """
    document = _render(
        findings, target=target, timestamp=timestamp, version=version
    )
    if output_path is not None:
        Path(output_path).write_text(document, encoding="utf-8")
    return document
