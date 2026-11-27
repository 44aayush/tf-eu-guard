"""Auditor report — an article-by-article NIS2/GDPR compliance matrix.

Produces a single self-contained ``.html`` file (embedded CSS, no JavaScript)
aimed at a compliance auditor rather than an engineer: an executive summary with
per-framework control counts, a table of contents, and one section per cited
article listing the failing resources and evidence.

Honesty note: only *failed* Checkov checks that map to a control are enriched,
so every article shown here has open findings. The report never claims a control
"passes" — absence of a finding is explicitly stated to not be evidence of
compliance. See ``docs/DECISIONS.md`` §11.
"""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from tf_eu_guard import __version__
from tf_eu_guard.mapping.coverage import RequirementResult
from tf_eu_guard.mapping.requirements import canonical_article_title
from tf_eu_guard.models import EnrichedFinding, Framework
from tf_eu_guard.reporting.baselined import baselined_html, baselined_unmapped_html
from tf_eu_guard.reporting.html_common import (
    badge_style,
    distinct_files,
    esc,
    file_location,
    severity_class,
    unmapped_html,
)
from tf_eu_guard.reporting.sorting import finding_sort_key, sort_findings
from tf_eu_guard.reporting.styles import (
    AUDITOR_CSS,
    CSP_META,
    FRAMEWORK_DOC,
    FRAMEWORK_ORDER,
    SUPPRESSED_CSS,
)
from tf_eu_guard.reporting.suppressed import SuppressedItem, suppressed_html, suppressed_items
from tf_eu_guard.reporting.waived import waived_html
from tf_eu_guard.reporting.weakening import weakening_html


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
    index: dict[Framework, dict[str, dict]] = {fw: {} for fw in FRAMEWORK_ORDER}
    for finding in sort_findings(findings):
        for art in finding.articles:
            bucket = index.setdefault(art.framework, {})
            title = canonical_article_title(art.framework, art.article) or art.title
            entry = bucket.setdefault(art.article, {"title": title, "findings": []})
            if not entry["title"] and title:
                entry["title"] = title
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
    for fw in FRAMEWORK_ORDER:
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
        "Each finding is a Checkov control failure mapped to one or more NIS2, "
        "GDPR, or project-policy references. The table below counts, per "
        "framework, the distinct "
        "articles with at least one open finding and the total findings citing "
        "that framework.</p>\n"
        "<table>\n<thead><tr><th>Framework</th>"
        "<th>Articles with open findings</th><th>Total findings</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>"
    )


def _requirement_table(rows: list[RequirementResult]) -> str:
    """Per-requirement counts of check results; counts only, no score."""
    body = []
    for row in rows:
        req = row.requirement
        note = "" if row.ran else " <em>No mapped check was evaluated.</em>"
        body.append(
            f"<tr><td>{esc(req.framework.value)} Art. {esc(req.article)} &mdash; "
            f"{esc(req.title)}</td><td>{esc(req.category.value)}</td>"
            f'<td class="num">{req.check_count}</td><td class="num">{row.ran}</td>'
            f'<td class="num">{row.passed}</td><td class="num">{row.failed}</td>'
            f'<td class="num">{row.suppressed}</td><td class="num">{row.waived}</td>'
            f"<td>{note}</td></tr>"
        )
    return (
        "<h2>Requirement evidence</h2>\n"
        "<p>Check results (resource &times; check) per requirement. Counts only: "
        "a passed check is evidence for its requirement, not a compliance score.</p>\n"
        "<table>\n<thead><tr><th>Requirement</th><th>Coverage label</th>"
        "<th>Mapped checks</th><th>Ran</th><th>Passed</th><th>Failed</th>"
        "<th>Suppressed</th><th>Waived</th><th>Note</th></tr></thead>\n<tbody>\n"
        + "\n".join(body)
        + "\n</tbody>\n</table>"
    )


def _toc(index: dict[Framework, dict[str, dict]]) -> str:
    """Table of contents linking to each article section."""
    blocks: list[str] = []
    for fw in FRAMEWORK_ORDER:
        articles = index.get(fw) or {}
        if not articles:
            continue
        items = []
        for article in sorted(articles, key=_article_sort_key):
            entry = articles[article]
            n = len(entry["findings"])
            title_suffix = f" &mdash; {esc(entry['title'])}" if entry["title"] else ""
            items.append(
                f'<li><a href="#{_anchor(fw, article)}">{esc(article)}{title_suffix}</a> ({n})</li>'
            )
        blocks.append(f"<strong>{esc(fw.value)}</strong>\n<ul>\n" + "\n".join(items) + "\n</ul>")
    return '<nav class="toc"><strong>Contents</strong>\n' + "\n".join(blocks) + "\n</nav>"


def _article_section(framework: Framework, article: str, entry: dict, version: str) -> str:
    """Render one article: heading, status, failing-resource table, doc link."""
    anchor = _anchor(framework, article)
    group = sorted(entry["findings"], key=finding_sort_key)
    title = entry["title"]

    rows = []
    for f in group:
        sev = f.severity
        rows.append(
            "<tr>"
            f'<td><span class="badge {severity_class(sev)}" '
            f"{badge_style(sev)}>{esc(sev.value)}</span></td>"
            f"<td><code>{esc(f.resource)}</code></td>"
            f"<td><code>{file_location(f)}</code></td>"
            f"<td><code>{esc(f.check_id)}</code><br>{esc(f.check_name)}</td>"
            "</tr>"
        )

    doc_name = FRAMEWORK_DOC.get(framework, "")
    doc = (
        f"https://github.com/44aayush/tf-eu-guard/blob/v{quote(version or __version__, safe='')}/docs/{doc_name}"
        if doc_name
        else ""
    )
    title_html = f' <span class="title-note">&mdash; {esc(title)}</span>' if title else ""
    doc_html = (
        f'<p class="doclink">Mapping rationale: <a href="{esc(doc)}">'
        f"<code>{esc(doc)}</code></a></p>\n"
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
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n" + doc_html + "</div>"
    )


def _provenance_html(provenance: dict[str, Any]) -> str:
    """Provenance table; every value is escaped (options come from user input)."""
    checks = provenance.get("checks") or {}
    rows = [
        ("Tool version", provenance.get("tool_version")),
        ("Checkov version", provenance.get("checkov_version")),
        ("Registry SHA-256", provenance.get("registry_sha256")),
        ("Registry files", ", ".join(provenance.get("registry_files") or [])),
        ("Commit", provenance.get("commit")),
        ("Resources scanned", provenance.get("resources_scanned")),
        ("Checks", ", ".join(f"{k}: {v}" for k, v in checks.items())),
        ("Options", json.dumps(provenance.get("options"), sort_keys=True)),
    ]
    body = "".join(
        f"<tr><th>{esc(label)}</th><td><code>{esc('' if v is None else str(v))}</code></td></tr>"
        for label, v in rows
    )
    return f'<h2 id="provenance">Provenance</h2>\n<table>{body}</table>'


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
    requirements: list[RequirementResult] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    baselined_unmapped: list[dict[str, Any]] | None = None,
    list_baselined_unmapped: bool = False,
    provenance: dict[str, Any] | None = None,
) -> str:
    """Assemble the complete auditor HTML document."""
    findings = sort_findings(findings)
    suppressed = suppressed or []
    waived = waived or []
    baselined = baselined or []
    known_unmapped = baselined_unmapped or []
    known_total = len(baselined) + len(known_unmapped)
    header = (
        '<a id="top"></a>\n<header>\n'
        "  <h1>tf-eu-guard &mdash; Compliance Audit Report</h1>\n"
        '  <p style="margin:4px 0 8px;font-family:system-ui,sans-serif">'
        "NIS2 (Directive 2022/2555, Art. 21), GDPR (Reg. 2016/679, Art. 32 &amp; 44), "
        "and project policy</p>\n"
        '  <div class="meta">'
        f"<span>Target: <code>{esc(target) or '&mdash;'}</code></span>"
        f"<span>Generated: {esc(timestamp) or '&mdash;'}</span>"
        "</div>\n"
        f"{weakening_html(weakening_settings)}"
        "</header>"
    )

    scope = (
        '<div class="scope"><strong>Scope &amp; limitations.</strong> '
        "This report lists only Checkov control failures that map to a NIS2, GDPR, "
        "or project-policy reference. It is an evidence aid for an auditor, not legal advice "
        "and is not a certification. "
        "An article not listed here was not exercised by a failing check &mdash; "
        "that is <em>not</em> evidence of compliance. Absence of a finding is not "
        "evidence of compliance."
        + (
            f" Checkov additionally reported <strong>{unmapped_count}</strong> "
            "failed check(s) with no current EU regulatory mapping; they are not "
            "shown in this report and were not assessed against any article."
            if unmapped_count
            else ""
        )
        + (
            f" <strong>{len(suppressed)}</strong> check(s) were suppressed by inline "
            "<code>checkov:skip</code> comments in the scanned code; they are listed "
            "in a separate section below, are not counted as open findings, and are "
            "not evidence that the underlying control is met."
            if suppressed
            else ""
        )
        + (
            f" <strong>{len(waived)}</strong> finding(s) are covered by a reviewed waiver; "
            "they are listed in a separate section below with owner, reason and expiry, "
            "are not counted as open findings, and are not evidence that the underlying "
            "control is met."
            if waived
            else ""
        )
        + (
            f" <strong>{known_total}</strong> finding(s) are already known from the "
            "baseline report; they are listed in a separate section below, do not "
            "affect the CI gate, and are still open."
            if known_total
            else ""
        )
        + "</div>"
    )

    if not findings:
        empty_body = (
            '<div class="empty"><h2 style="margin-top:0;border:none">'
            "No mapped findings</h2>"
            "<p>No failed Checkov checks mapped to a compliance control for this "
            "target. This does not by itself demonstrate compliance.</p></div>"
        )
        if unmapped_count:
            empty_body = (
                '<div class="empty"><h2 style="margin-top:0;border:none">'
                f"No mapped findings &mdash; {unmapped_count} unmapped</h2>"
                "<p>No failed Checkov checks mapped to a compliance control for "
                f"this target, but <strong>{unmapped_count}</strong> failed check(s) "
                "have no current EU regulatory mapping and are not shown here. "
                "This does not by itself demonstrate compliance.</p></div>"
            )
        if (suppressed or waived or known_total) and not unmapped_count:
            empty_body = (
                '<div class="empty"><h2 style="margin-top:0;border:none">'
                f"No active mapped findings &mdash; {len(suppressed)} suppressed, "
                f"{len(waived)} waived, {known_total} known in baseline</h2>"
                "<p>Every failed check that maps to a compliance control was suppressed "
                "by an inline comment, covered by a waiver or already known from the "
                "baseline. This does not by itself demonstrate "
                "compliance.</p></div>"
            )
        parts = [header, scope, empty_body]
        if requirements:
            parts.append(_requirement_table(requirements))
        body = "\n".join(parts)
    else:
        index = _build_index(findings)
        sections: list[str] = [header, scope, _executive_summary(findings, index)]
        if requirements:
            sections.append(_requirement_table(requirements))
        sections.append(_toc(index))
        for fw in FRAMEWORK_ORDER:
            articles = index.get(fw) or {}
            if not articles:
                continue
            sections.append(f"<h2>{esc(fw.value)} controls</h2>")
            for article in sorted(articles, key=_article_sort_key):
                sections.append(_article_section(fw, article, articles[article], version))
        body = "\n".join(sections)

    if unmapped:
        body = f"{body}\n{unmapped_html(unmapped)}"

    if suppressed:
        body = f"{body}\n{suppressed_html(suppressed)}"

    if waived:
        body = f"{body}\n{waived_html(waived)}"

    if baselined:
        body = f"{body}\n{baselined_html(baselined)}"

    if known_unmapped:
        body = f"{body}\n{baselined_unmapped_html(known_unmapped, list_baselined_unmapped)}"

    if provenance:
        body = f"{body}\n{_provenance_html(provenance)}"

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
        f"{CSP_META}\n"
        "<title>tf-eu-guard Compliance Audit Report</title>\n"
        f"<style>{AUDITOR_CSS}{SUPPRESSED_CSS}</style>\n"
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
    unmapped_count: int = 0,
    unmapped: list[dict[str, Any]] | None = None,
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    requirements: list[RequirementResult] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    baselined_unmapped: list[dict[str, Any]] | None = None,
    list_baselined_unmapped: bool = False,
    provenance: dict[str, Any] | None = None,
) -> str:
    """Generate the self-contained HTML auditor / compliance-matrix report.

    Args:
        findings: Enriched findings (as produced by ``enrich_findings``).
        target: Human-readable scan target (shown in the header).
        timestamp: Human-readable scan time (shown in the header/footer).
        version: tf-eu-guard version (shown in the footer).
        output_path: If given, the HTML is also written to this path (UTF-8).
        unmapped: Raw unmapped Checkov dicts; when given, listed in full
            (``--show-unmapped``).
        unmapped_count: Checkov findings with no registry mapping — called out
            in the scope note so they are present-but-unmapped, not absent.
        suppressed: Mapped findings suppressed by inline ``checkov:skip``
            comments — listed in their own section, never counted as open.
        suppressed_unmapped: Raw Checkov dicts for suppressed unmapped checks.
        requirements: Per-requirement evidence rows; ``None`` omits the table.

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
        requirements=requirements,
        weakening_settings=weakening_settings,
        baselined=baselined,
        baselined_unmapped=baselined_unmapped,
        list_baselined_unmapped=list_baselined_unmapped,
        provenance=provenance,
    )
    if output_path is not None:
        Path(output_path).write_text(document, encoding="utf-8")
    return document
