"""Developer HTML report — the ``dev`` findings view as a shareable HTML file.

Carries the same information as the terminal ``dev`` report but rendered as a
single self-contained HTML file (embedded CSS, no JavaScript, no external
assets) so it can be attached to a pull request or shared without a terminal.

Where the *security* report groups by severity for triage, this developer view
groups by **file** — the unit a developer actually edits — with findings inside
each file ordered most-severe first. The finding card itself is shared with the
security report via :func:`tf_eu_guard.reporting._html_common.finding_card`.
"""

from pathlib import Path

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting._html_common import (
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    distinct_files,
    esc,
    finding_card,
    severity_counts,
)

# Card/badge/article styling mirrors the security report so a finding looks the
# same wherever it appears; the layout rules (file sections, chips) are local.
_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    max-width: 1000px; margin: 40px auto; padding: 0 20px;
    color: #1a1a1a; background: #fafafa; line-height: 1.5;
  }
  header { border-bottom: 3px solid #2c3e50; padding-bottom: 16px; margin-bottom: 24px; }
  header h1 { margin: 0 0 6px; font-size: 1.7rem; }
  header .meta { color: #555; font-size: 0.9rem; }
  header .meta span { margin-right: 18px; white-space: nowrap; }

  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 4px 0 8px; }
  .chip {
    background: #fff; border: 1px solid #e2e2e2; border-radius: 999px;
    padding: 4px 12px; font-size: 0.85rem; box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }
  .chip b { font-variant-numeric: tabular-nums; }

  .file-group { margin: 26px 0 8px; }
  h2.file {
    font-size: 1.05rem; margin: 0 0 8px; padding: 8px 12px;
    background: #eef2f7; border: 1px solid #d6e0ea; border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all;
  }
  h2.file .fcount { float: right; color: #667; font-size: 0.82rem; font-weight: 400; }

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
    .chip, .finding { background: #21242b; border-color: #33373f; }
    h2.file { background: #2b3140; border-color: #3a4256; }
    dl.meta dt, header .meta { color: #aab; }
    .remediation pre { background: #1b1d22; border-color: #33373f; }
    .art { background: #2b3140; border-color: #3a4256; color: #cdd7e5; }
  }
"""


def _severity_rank(finding: EnrichedFinding) -> int:
    """Sort key placing the most severe findings first (unknown severities last)."""
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return order.get(finding.severity, len(SEVERITY_ORDER))


def _summary_chips(findings: list[EnrichedFinding]) -> str:
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
    return '<section class="chips">\n' + "\n".join(chips) + "\n</section>"


def _file_section(file_path: str, group: list[EnrichedFinding]) -> str:
    """Render one file heading plus its findings (most severe first)."""
    group = sorted(group, key=lambda f: (_severity_rank(f), f.check_id))
    n = len(group)
    heading = (
        '<div class="file-group">\n'
        f'<h2 class="file">{esc(file_path)}'
        f'<span class="fcount">{n} finding{"" if n == 1 else "s"}</span></h2>'
    )
    cards = "\n".join(finding_card(f) for f in group)
    return f"{heading}\n{cards}\n</div>"


def _render(
    findings: list[EnrichedFinding], *, target: str, timestamp: str, version: str
) -> str:
    """Assemble the complete HTML document."""
    header = (
        "<header>\n"
        "  <h1>tf-eu-guard &mdash; Developer Report</h1>\n"
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
        # Group by file; files sorted alphabetically for a stable, navigable layout.
        by_file: dict[str, list[EnrichedFinding]] = {}
        for f in findings:
            by_file.setdefault(f.file_path, []).append(f)
        sections = [_summary_chips(findings), "<h2>Findings by file</h2>"]
        sections.extend(
            _file_section(path, by_file[path]) for path in sorted(by_file)
        )
        body = "\n".join(sections)

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
        "<title>tf-eu-guard Developer Report</title>\n"
        f"<style>{_CSS}</style>\n"
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
) -> str:
    """Generate the self-contained developer HTML report (findings grouped by file).

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
