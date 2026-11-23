"""Markdown summary report (GitHub step summary / PR comment friendly)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.sorting import sort_findings, sorted_articles

if TYPE_CHECKING:
    from tf_eu_guard.cli.pipeline import ScanFindings

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def md_escape(value: object) -> str:
    """Escape text for a Markdown table cell; resource names are untrusted."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def severity_counts(findings: list[EnrichedFinding]) -> dict[str, int]:
    """Active mapped findings per severity (keys in ``_SEVERITIES`` order)."""
    counts = dict.fromkeys(_SEVERITIES, 0)
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def render_markdown(result: ScanFindings, *, target: str, version: str, max_rows: int = 50) -> str:
    """Render the summary: severity table, weakening settings, top findings, counts."""
    counts = severity_counts(result.findings)
    unmapped = len(result.unmapped)
    suppressed = len(result.suppressed) + len(result.suppressed_unmapped)
    lines = [
        f"# tf-eu-guard {md_escape(version)} report",
        "",
        f"Target: {md_escape(target)}",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
        *(f"| {name.title()} | {counts[name]} |" for name in _SEVERITIES),
        "",
    ]
    if result.weakening_settings:
        lines += ["**Settings that reduce findings:**", ""]
        lines += [f"- {md_escape(s)}" for s in result.weakening_settings]
        lines.append("")
    rank = {name: index for index, name in enumerate(_SEVERITIES)}
    ordered = sorted(sort_findings(result.findings), key=lambda f: rank[f.severity.value])
    if ordered:
        lines += [
            "| Severity | Check | Resource | Location | Articles |",
            "| --- | --- | --- | --- | --- |",
        ]
        for finding in ordered[:max_rows]:
            start = finding.file_line_range[0] if finding.file_line_range else 0
            articles = ", ".join(
                f"{a.framework.value} {a.article}" for a in sorted_articles(finding)
            )
            lines.append(
                f"| {finding.severity.value} | {md_escape(finding.check_id)} "
                f"| {md_escape(finding.resource)} "
                f"| {md_escape(f'{finding.file_path}:{start}')} | {md_escape(articles)} |"
            )
        if len(ordered) > max_rows:
            lines += ["", f"... and {len(ordered) - max_rows} more"]
        lines.append("")
    lines.append(
        f"Unmapped: {unmapped} | Suppressed: {suppressed} | "
        f"Waived: {len(result.waived)} | Baselined: {len(result.baselined)}"
    )
    return "\n".join(lines) + "\n"


def render_counts(result: ScanFindings) -> str:
    """``key=value`` lines in GitHub ``$GITHUB_OUTPUT`` format."""
    counts = {k.lower(): v for k, v in severity_counts(result.findings).items()}
    counts["unmapped"] = len(result.unmapped)
    counts["suppressed"] = len(result.suppressed) + len(result.suppressed_unmapped)
    counts["waived"] = len(result.waived)
    counts["baselined"] = len(result.baselined)
    counts["total"] = len(result.findings) + len(result.unmapped)
    return "".join(f"{key}={value}\n" for key, value in counts.items())
