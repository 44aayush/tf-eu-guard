"""Shared helpers for the self-contained HTML report generators.

The ``security`` and ``auditor`` reporters both emit a single, dependency-free
HTML file (embedded CSS, no JavaScript, no external assets). These helpers keep
the severity palette, HTML escaping, and small formatting utilities consistent
between the two.
"""

import html

from tf_eu_guard.models import EnrichedFinding, Severity

# Severity display order (most to least severe). INFO is included for
# completeness even though the registry currently only emits CRITICAL/HIGH/MEDIUM.
SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Accessible, print-friendly palette (works on white backgrounds and in PDF export).
SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#d4ac0d",
    Severity.LOW: "#2980b9",
    Severity.INFO: "#7f8c8d",
}


def esc(value: object) -> str:
    """HTML-escape any value for safe interpolation (``None`` becomes ``""``).

    ``html.escape`` escapes ``&``, ``<``, ``>`` and — with the default
    ``quote=True`` — both quote characters, so the result is safe in both
    element text and double/single-quoted attribute values.
    """
    if value is None:
        return ""
    return html.escape(str(value))


def severity_class(severity: Severity) -> str:
    """CSS class suffix for a severity, e.g. ``sev-critical``."""
    return f"sev-{severity.value.lower()}"


def severity_counts(findings: list[EnrichedFinding]) -> dict[Severity, int]:
    """Count findings per severity, in :data:`SEVERITY_ORDER`."""
    counts: dict[Severity, int] = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def line_range(finding: EnrichedFinding) -> str | None:
    """Render a finding's line range as ``start-end``, or ``None`` if unknown.

    Checkov reports ``[0, 0]`` for frameworks with no meaningful line anchor —
    e.g. terraform_plan JSON (the whole plan is one line). Returning ``None``
    lets callers omit the reference instead of printing a meaningless range.
    """
    lr = finding.file_line_range or []
    if len(lr) >= 2 and (lr[0] or lr[1]):  # non-degenerate range
        return f"{lr[0]}-{lr[1]}"
    if len(lr) == 1 and lr[0]:
        return str(lr[0])
    return None


def file_location(finding: EnrichedFinding) -> str:
    """Render ``file_path`` plus its line range, omitting the latter if unknown."""
    location = esc(finding.file_path)
    lines = line_range(finding)
    if lines:
        location = f"{location}:{esc(lines)}"
    return location


def distinct_files(findings: list[EnrichedFinding]) -> int:
    """Number of distinct files referenced by the findings."""
    return len({f.file_path for f in findings})


def finding_card(finding: EnrichedFinding) -> str:
    """Render one finding as a self-contained HTML card. All fields are escaped.

    Shared by the security and developer HTML reports so the two stay in sync.
    The markup uses the ``.finding`` / ``.badge`` / ``.art`` / ``.remediation`` /
    ``.doc`` classes, which each report's embedded stylesheet defines.
    """
    sev = finding.severity
    sev_cls = severity_class(sev)
    parts: list[str] = [
        f'<article class="finding {sev_cls}" style="border-left-color:{SEVERITY_COLOR[sev]}">',
        '  <div class="finding-head">',
        f'    <span class="badge" style="background:{SEVERITY_COLOR[sev]}">{esc(sev.value)}</span>',
        f'    <span class="cid">{esc(finding.check_id)}</span>',
        f'    <span class="cname">{esc(finding.check_name)}</span>',
        "  </div>",
        '  <dl class="meta">',
        f"    <dt>Resource</dt><dd><code>{esc(finding.resource)}</code></dd>",
        f"    <dt>File</dt><dd><code>{file_location(finding)}</code></dd>",
    ]
    if finding.articles:
        badges = " ".join(
            f'<span class="art">{esc(a.framework.value)} {esc(a.article)}</span>'
            for a in finding.articles
        )
        parts.append(f"    <dt>Compliance</dt><dd>{badges}</dd>")
    parts.append("  </dl>")

    if finding.risk_explanation:
        parts.append(f'  <p class="risk">{esc(finding.risk_explanation)}</p>')
    if finding.remediation:
        parts.append(
            '  <div class="remediation"><h4>Remediation</h4>'
            f"<pre>{esc(finding.remediation.strip())}</pre></div>"
        )
    if finding.guideline:
        parts.append(
            f'  <a class="doc" href="{esc(finding.guideline)}" '
            'rel="noopener noreferrer" target="_blank">Documentation &#8599;</a>'
        )
    parts.append("</article>")
    return "\n".join(parts)
