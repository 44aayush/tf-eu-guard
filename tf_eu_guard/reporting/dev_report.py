"""Developer-focused terminal report."""

from typing import Any

from rich.console import Console
from rich.markup import escape

from tf_eu_guard.models import EnrichedFinding, Severity
from tf_eu_guard.reporting.html_common import line_range, safe_guideline
from tf_eu_guard.reporting.sorting import finding_sort_key, sort_findings, sorted_articles
from tf_eu_guard.reporting.styles import SEVERITY_COLOR_TERMINAL, SEVERITY_ORDER
from tf_eu_guard.reporting.suppressed import SuppressedItem, suppressed_items


def _group_findings_by_file(
    findings: list[EnrichedFinding],
) -> dict[str, list[EnrichedFinding]]:
    """Group findings by file after applying the shared stable ordering."""
    findings_by_file: dict[str, list[EnrichedFinding]] = {}
    for finding in sort_findings(findings):
        findings_by_file.setdefault(finding.file_path, []).append(finding)
    return findings_by_file


def _finding_severity_sort_key(finding: EnrichedFinding) -> tuple[int, tuple]:
    """Return the presentation order for findings within one file."""
    severity_rank = (
        SEVERITY_ORDER.index(finding.severity)
        if finding.severity in SEVERITY_ORDER
        else len(SEVERITY_ORDER)
    )
    return severity_rank, finding_sort_key(finding)


def _sort_findings_within_file(
    findings: list[EnrichedFinding],
) -> list[EnrichedFinding]:
    """Sort file-local findings by severity, then by their stable identity."""
    return sorted(findings, key=_finding_severity_sort_key)


def _suppressed_lines(items: list[SuppressedItem]) -> list[str]:
    """Rich-markup lines for the 'Suppressed by inline comment' section."""
    lines = [
        f"\n[bold yellow]Suppressed by inline comment ({len(items)})[/bold yellow]",
        "[dim]These checks failed but were suppressed in the scanned code. They are "
        "not active findings and do not affect --fail-on-severity / --fail-on-any.[/dim]",
    ]
    for item in items:
        lines.append(
            f"\n  [yellow]○[/yellow] [bold]{escape(item.check_id)}[/bold]: "
            f"{escape(item.check_name)}"
        )
        lines.append(f"    [dim]Resource:[/dim] {escape(item.resource)}")
        lines.append(f"    [dim]File:[/dim] {escape(item.location)}")
        lines.append(f"    [dim]Reason:[/dim] {escape(item.reason_text)}")
        if not item.mapped:
            lines.append("    [dim]No current EU regulatory mapping[/dim]")
    return lines


def generate_dev_report(
    findings: list[EnrichedFinding],
    unmapped_count: int = 0,
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
) -> None:
    """
    Generate and print developer-focused terminal report.

    Args:
        findings: List of enriched findings with compliance mappings
        unmapped_count: Number of Checkov findings with no registry mapping —
            surfaced as a count so they are present-but-unmapped, not absent
        suppressed: Mapped findings suppressed by inline ``checkov:skip``
            comments, shown in their own section and never counted as active
        suppressed_unmapped: Raw Checkov dicts for suppressed unmapped checks
    """
    console = Console()
    suppressed_list = suppressed_items(suppressed, suppressed_unmapped)

    if not findings and not unmapped_count and not suppressed_list:
        console.print("\n[green]✓ No compliance findings![/green]\n")
        return

    # Header
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]")
    console.print("[bold]  tf-eu-guard: EU Compliance Scan Report[/bold]")
    console.print("[bold]═══════════════════════════════════════════════════[/bold]\n")

    if not findings and not unmapped_count:
        # Only suppressed findings — not a clean bill of health.
        console.print(
            f"[yellow]No active findings; {len(suppressed_list)} suppressed by "
            f"inline comment.[/yellow]"
        )
        for line in _suppressed_lines(suppressed_list):
            console.print(line)
        console.print()
        return

    if not findings:
        # Unmapped findings only — the scan is NOT clean, say so explicitly
        # instead of printing the "no findings" success banner.
        console.print(
            f"[yellow]No mapped compliance findings, but {unmapped_count} unmapped "
            f"Checkov finding(s) exist (no current EU regulatory mapping):[/yellow]"
        )
        console.print(
            "[dim]Checkov reported failures this tool cannot map to NIS2/GDPR — "
            "review them with a plain Checkov run.[/dim]\n"
        )
        if suppressed_list:
            for line in _suppressed_lines(suppressed_list):
                console.print(line)
            console.print()
        return

    # Summary
    severity_counts: dict[Severity, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    console.print(f"[bold]Total Findings:[/bold] {len(findings)}")
    for severity in SEVERITY_ORDER:
        if severity in severity_counts:
            color = SEVERITY_COLOR_TERMINAL[severity]
            console.print(f"  [{color}]●[/{color}] {severity.value}: {severity_counts[severity]}")
    if unmapped_count:
        console.print(
            f"  [dim]● Unmapped Checkov findings: {unmapped_count} "
            f"(no current EU regulatory mapping — not listed below)[/dim]"
        )
    if suppressed_list:
        console.print(
            f"  [yellow]○ Suppressed by inline comment: {len(suppressed_list)} "
            f"(not counted above — listed at the end)[/yellow]"
        )
    console.print()

    findings_by_file = _group_findings_by_file(findings)

    # Display findings
    for file_path, file_findings in sorted(findings_by_file.items()):
        console.print(f"\n[bold cyan]File: {escape(str(file_path))}[/bold cyan]")

        sorted_findings = _sort_findings_within_file(file_findings)

        for finding in sorted_findings:
            # Severity badge
            severity_color = SEVERITY_COLOR_TERMINAL[finding.severity]

            console.print(
                f"\n  [{severity_color}]●[/{severity_color}] [bold]"
                f"{escape(str(finding.check_id))}[/bold]: "
                f"{escape(str(finding.check_name))}"
            )
            console.print(f"    [dim]Resource:[/dim] {escape(str(finding.resource))}")
            line_ref = line_range(finding)
            if line_ref:
                console.print(f"    [dim]Lines:[/dim] {escape(str(line_ref))}")
            console.print(
                f"    [dim]Severity:[/dim] [{severity_color}]"
                f"{escape(finding.severity.value)}[/{severity_color}]"
            )

            # Compliance articles
            if finding.articles:
                articles_str = ", ".join(
                    f"[bold]{escape(str(a.framework.value))}[/bold] {escape(str(a.article))}"
                    for a in sorted_articles(finding)
                )
                console.print(f"    [dim]Compliance:[/dim] {articles_str}")

            # Risk explanation
            console.print(f"\n    [italic]{escape(str(finding.risk_explanation))}[/italic]")

            # Remediation
            if finding.remediation:
                console.print("\n    [bold]Remediation:[/bold]")
                # Indent remediation code
                for line in finding.remediation.strip().split("\n"):
                    console.print(f"      [dim]{escape(line)}[/dim]")

            # Guideline link — scheme-validated: a javascript: guideline must
            # not become a clickable link in terminal markup either, and Rich
            # [link=...] interpolates the value raw (no markup escaping).
            guideline = safe_guideline(finding.guideline)
            if guideline:
                console.print(f"\n    [link={escape(guideline)}]→ Documentation[/link]")

    if suppressed_list:
        for line in _suppressed_lines(suppressed_list):
            console.print(line)

    # Footer
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]\n")
