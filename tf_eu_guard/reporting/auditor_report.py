"""Auditor report — an article-by-article NIS2/GDPR compliance matrix.

Produces a single self-contained ``.html`` file (embedded CSS, no JavaScript)
aimed at a compliance auditor rather than an engineer: an executive summary with
per-framework control counts, a table of contents, and one section per cited
article listing the failing resources and evidence.

Honesty note: only *failed* Checkov checks that map to a control are enriched,
so every article shown here has open findings. The report never claims a control
"passes" — absence of a finding is explicitly stated to not be evidence of
compliance. See ``PROJECT_PLAN.md`` §4.3.
"""

import re
from pathlib import Path

from tf_eu_guard.models import EnrichedFinding, Framework
from tf_eu_guard.reporting._html_common import (
    SEVERITY_COLOR,
    distinct_files,
    esc,
    line_range,
    severity_class,
)

# Framework display order and the mapping-doc each framework links to.
_FRAMEWORK_ORDER: list[Framework] = [Framework.NIS2, Framework.GDPR]
_FRAMEWORK_DOC: dict[Framework, str] = {
    Framework.NIS2: "docs/nis2-mapping.md",
    Framework.GDPR: "docs/gdpr-mapping.md",
}

_CSS = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: Georgia, "Times New Roman", serif;
    max-width: 980px; margin: 40px auto; padding: 0 24px;
    color: #1a1a1a; background: #fff; line-height: 1.6;
  }
  header { border-bottom: 3px double #2c3e50; padding-bottom: 18px; margin-bottom: 24px; }
  header h1 { margin: 0 0 6px; font-size: 1.8rem; }
  header .meta { color: #555; font-size: 0.9rem; font-family: system-ui, sans-serif; }
  header .meta span { margin-right: 18px; }
  h2 { font-size: 1.35rem; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 40px; }
  h3 { font-size: 1.1rem; margin: 28px 0 6px; }

  .scope {
    background: #fff8e1; border: 1px solid #f0d98c; border-radius: 6px;
    padding: 12px 16px; font-family: system-ui, sans-serif; font-size: 0.9rem; margin: 18px 0;
  }
  table { border-collapse: collapse; width: 100%; font-family: system-ui, sans-serif; font-size: 0.92rem; margin: 12px 0; }
  th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }
  th { background: #f2f4f7; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }

  nav.toc { font-family: system-ui, sans-serif; font-size: 0.92rem; background: #f7f8fa; border: 1px solid #e2e2e2; border-radius: 6px; padding: 14px 20px; }
  nav.toc ul { margin: 6px 0; padding-left: 20px; }
  nav.toc a { color: #2c3e50; text-decoration: none; }
  nav.toc a:hover { text-decoration: underline; }

  .article { margin-bottom: 8px; }
  .article .title-note { color: #555; font-weight: normal; }
  .status {
    display: inline-block; font-family: system-ui, sans-serif; font-size: 0.8rem; font-weight: 700;
    background: #fdecea; color: #b03a2e; border: 1px solid #f5b7b1; border-radius: 12px; padding: 2px 10px;
  }
  .badge {
    display: inline-block; color: #fff; font-size: 0.7rem; font-weight: 700; font-family: system-ui, sans-serif;
    padding: 1px 7px; border-radius: 10px; text-transform: uppercase;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88rem; }
  .doclink { font-family: system-ui, sans-serif; font-size: 0.85rem; }
  .backtop { font-family: system-ui, sans-serif; font-size: 0.78rem; margin-left: 10px; }
  .backtop a { color: #888; text-decoration: none; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #ccc; color: #777; font-size: 0.82rem; font-family: system-ui, sans-serif; }
  .empty { background: #eafaf1; border: 1px solid #abebc6; color: #1e6b43; padding: 24px; border-radius: 8px; text-align: center; font-family: system-ui, sans-serif; }
  @media print { body { max-width: none; margin: 0; } nav.toc { page-break-after: always; } }
"""


def _anchor(framework: Framework, article: str) -> str:
    """Stable, collision-resistant anchor id, e.g. ``nis2-art-21-2-i``."""
    slug = re.sub(r"[^a-z0-9]+", "-", f"{framework.value}-{article}".lower())
    return slug.strip("-")


def _build_index(
    findings: list[EnrichedFinding],
) -> dict[Framework, dict[str, dict]]:
    """Group findings by framework then article.

    Returns ``{framework: {article: {"title": str, "findings": [...]}}}``,
    preserving each article's title from its :class:`ArticleReference`.
    """
    index: dict[Framework, dict[str, dict]] = {fw: {} for fw in _FRAMEWORK_ORDER}
    for finding in findings:
        for art in finding.articles:
            bucket = index.setdefault(art.framework, {})
            entry = bucket.setdefault(art.article, {"title": art.title, "findings": []})
            if not entry["title"] and art.title:
                entry["title"] = art.title
            entry["findings"].append(finding)
    return index


def _article_sort_key(article: str) -> tuple:
    """Sort article labels numerically where possible (``Art. 21`` < ``Art. 44``)."""
    nums = tuple(int(n) for n in re.findall(r"\d+", article))
    return (nums, article)


def _executive_summary(
    findings: list[EnrichedFinding], index: dict[Framework, dict[str, dict]]
) -> str:
    """Per-framework control-count table plus an overall line."""
    rows: list[str] = []
    for fw in _FRAMEWORK_ORDER:
        articles = index.get(fw) or {}
        n_articles = len(articles)
        n_findings = sum(1 for f in findings if fw in f.frameworks)
        rows.append(
            f"<tr><td>{esc(fw.value)}</td>"
            f'<td class="num">{n_articles}</td>'
            f'<td class="num">{n_findings}</td></tr>'
        )
    return (
        "<h2>Executive summary</h2>\n"
        f"<p>This scan surfaced <strong>{len(findings)}</strong> compliance "
        f"findings across <strong>{distinct_files(findings)}</strong> file(s). "
        "Each finding is a Checkov control failure mapped to one or more NIS2 / "
        "GDPR articles. The table below counts, per framework, the distinct "
        "articles with at least one open finding and the total findings citing "
        "that framework.</p>\n"
        "<table>\n<thead><tr><th>Framework</th>"
        "<th>Articles with open findings</th><th>Total findings</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>"
    )


def _toc(index: dict[Framework, dict[str, dict]]) -> str:
    """Table of contents linking to each article section."""
    blocks: list[str] = []
    for fw in _FRAMEWORK_ORDER:
        articles = index.get(fw) or {}
        if not articles:
            continue
        items = []
        for article in sorted(articles, key=_article_sort_key):
            entry = articles[article]
            n = len(entry["findings"])
            title_suffix = f" &mdash; {esc(entry['title'])}" if entry["title"] else ""
            items.append(
                f'<li><a href="#{_anchor(fw, article)}">{esc(article)}'
                f"{title_suffix}</a> ({n})</li>"
            )
        blocks.append(
            f"<strong>{esc(fw.value)}</strong>\n<ul>\n" + "\n".join(items) + "\n</ul>"
        )
    return '<nav class="toc"><strong>Contents</strong>\n' + "\n".join(blocks) + "\n</nav>"


def _article_section(
    framework: Framework, article: str, entry: dict
) -> str:
    """Render one article: heading, status, failing-resource table, doc link."""
    anchor = _anchor(framework, article)
    group = sorted(entry["findings"], key=lambda f: (f.file_path, f.check_id))
    title = entry["title"]

    rows = []
    for f in group:
        sev = f.severity
        rows.append(
            "<tr>"
            f'<td><span class="badge {severity_class(sev)}" '
            f'style="background:{SEVERITY_COLOR[sev]}">{esc(sev.value)}</span></td>'
            f"<td><code>{esc(f.resource)}</code></td>"
            f"<td><code>{esc(f.file_path)}:{esc(line_range(f))}</code></td>"
            f"<td><code>{esc(f.check_id)}</code><br>{esc(f.check_name)}</td>"
            "</tr>"
        )

    doc = _FRAMEWORK_DOC.get(framework, "")
    title_html = (
        f" <span class=\"title-note\">&mdash; {esc(title)}</span>" if title else ""
    )
    doc_html = (
        f'<p class="doclink">Mapping rationale: <code>{esc(doc)}</code></p>\n'
        if doc
        else ""
    )
    return (
        f'<div class="article" id="{anchor}">\n'
        f"<h3>{esc(framework.value)} {esc(article)}{title_html}"
        f'<span class="backtop"><a href="#top">&#8593; top</a></span></h3>\n'
        f'<p><span class="status">OPEN &mdash; {len(group)} finding(s)</span></p>\n'
        "<table>\n<thead><tr><th>Severity</th><th>Resource</th>"
        "<th>Location</th><th>Failed control</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n"
        + doc_html
        + "</div>"
    )


def _render(
    findings: list[EnrichedFinding], *, target: str, timestamp: str, version: str
) -> str:
    """Assemble the complete auditor HTML document."""
    header = (
        '<a id="top"></a>\n<header>\n'
        "  <h1>tf-eu-guard &mdash; Compliance Audit Report</h1>\n"
        "  <p style=\"margin:4px 0 8px;font-family:system-ui,sans-serif\">"
        "NIS2 (Directive 2022/2555, Art. 21) &amp; GDPR (Reg. 2016/679, Art. 32 &amp; 44)</p>\n"
        '  <div class="meta">'
        f'<span>Target: <code>{esc(target) or "&mdash;"}</code></span>'
        f"<span>Generated: {esc(timestamp) or '&mdash;'}</span>"
        "</div>\n</header>"
    )

    scope = (
        '<div class="scope"><strong>Scope &amp; limitations.</strong> '
        "This report lists only Checkov control failures that map to a NIS2 or "
        "GDPR article. It is an evidence aid for an auditor, not a certification. "
        "An article not listed here was not exercised by a failing check &mdash; "
        "that is <em>not</em> evidence of compliance.</div>"
    )

    if not findings:
        body = (
            f"{header}\n{scope}\n"
            '<div class="empty"><h2 style="margin-top:0;border:none">No mapped findings</h2>'
            "<p>No failed Checkov checks mapped to a NIS2 or GDPR control for this "
            "target. This does not by itself demonstrate compliance.</p></div>"
        )
    else:
        index = _build_index(findings)
        sections: list[str] = [header, scope, _executive_summary(findings, index), _toc(index)]
        for fw in _FRAMEWORK_ORDER:
            articles = index.get(fw) or {}
            if not articles:
                continue
            sections.append(f"<h2>{esc(fw.value)} controls</h2>")
            for article in sorted(articles, key=_article_sort_key):
                sections.append(_article_section(fw, article, articles[article]))
        body = "\n".join(sections)

    footer = (
        "<footer>Generated by tf-eu-guard"
        f"{' v' + esc(version) if version else ''}"
        f"{' on ' + esc(timestamp) if timestamp else ''}.</footer>"
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>tf-eu-guard Compliance Audit Report</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        f"{body}\n{footer}\n"
        "</body>\n</html>\n"
    )


def generate_auditor_report(
    findings: list[EnrichedFinding],
    *,
    target: str = "",
    timestamp: str = "",
    version: str = "",
    output_path: Path | None = None,
) -> str:
    """Generate the self-contained HTML auditor / compliance-matrix report.

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
