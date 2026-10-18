"""Developer-focused terminal report."""

from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from tf_eu_guard.models import EnrichedFinding, ScanReport, Severity
from tf_eu_guard.reporting.base import BaseReporter
from tf_eu_guard.reporting.html_common import line_range, safe_guideline
from tf_eu_guard.reporting.sorting import finding_sort_key, sort_findings, sorted_articles
from tf_eu_guard.reporting.styles import SEVERITY_COLOR_TERMINAL, SEVERITY_ORDER


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


class DevReporter(BaseReporter):
    """Terminal-first report optimized for developers."""

    def __init__(self):
        self.console = Console()

    def generate(self, report: ScanReport, output_path: Path | None = None) -> str:
        """Generate developer-focused terminal report."""
        findings_by_file = _group_findings_by_file(report.findings)

        report_lines = []
        report_lines.append("\n[bold]tf-eu-guard scan results[/bold]")
        report_lines.append(f"Target: {escape(str(report.target_path))}")
        report_lines.append(f"Timestamp: {escape(str(report.scan_timestamp))}")
        report_lines.append(
            f"\nFindings: {report.total_failed} failed / {report.total_checks_run} total\n"
        )

        for file_path, findings in sorted(findings_by_file.items()):
            report_lines.append(f"\n[bold cyan]{escape(str(file_path))}[/bold cyan]")

            sorted_findings = _sort_findings_within_file(findings)

            for finding in sorted_findings:
                severity_color = SEVERITY_COLOR_TERMINAL[finding.severity]

                report_lines.append(
                    f"\n  [{severity_color}]●[/{severity_color}] "
                    f"{escape(str(finding.check_id))}: {escape(str(finding.check_name))}"
                )
                report_lines.append(f"    Resource: {escape(str(finding.resource))}")
                line_ref = line_range(finding)
                if line_ref:
                    report_lines.append(f"    Lines: {escape(str(line_ref))}")
                report_lines.append(
                    f"    Severity: [{severity_color}]{escape(finding.severity.value)}"
                    f"[/{severity_color}]"
                )

                if finding.articles:
                    articles_str = ", ".join(
                        f"{escape(str(a.framework.value))} {escape(str(a.article))}"
                        for a in sorted_articles(finding)
                    )
                    report_lines.append(f"    Compliance: {articles_str}")

                report_lines.append(
                    f"\n    [dim]{escape(str(finding.risk_explanation))}[/dim]"
                )

                if finding.remediation:
                    report_lines.append("\n    [bold]Fix:[/bold]")
                    report_lines.append(f"    {escape(str(finding.remediation))}")

        report_text = "\n".join(report_lines)

        if output_path:
            with open(output_path, "w") as f:
                # Parse the known report markup so escaped user brackets remain
                # literal instead of being removed by a broad regex.
                f.write(Text.from_markup(report_text).plain)

        return report_text


def generate_dev_report(
    findings: list[EnrichedFinding], unmapped_count: int = 0
) -> None:
    """
    Generate and print developer-focused terminal report.

    Args:
        findings: List of enriched findings with compliance mappings
        unmapped_count: Number of Checkov findings with no registry mapping —
            surfaced as a count so they are present-but-unmapped, not absent
    """
    console = Console()

    if not findings and not unmapped_count:
        console.print("\n[green]✓ No compliance findings![/green]\n")
        return

    # Header
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]")
    console.print("[bold]  tf-eu-guard: EU Compliance Scan Report[/bold]")
    console.print("[bold]═══════════════════════════════════════════════════[/bold]\n")

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
                    f"[bold]{escape(str(a.framework.value))}[/bold] "
                    f"{escape(str(a.article))}"
                    for a in sorted_articles(finding)
                )
                console.print(f"    [dim]Compliance:[/dim] {articles_str}")

            # Risk explanation
            console.print(
                f"\n    [italic]{escape(str(finding.risk_explanation))}[/italic]"
            )

            # Remediation
            if finding.remediation:
                console.print("\n    [bold]Remediation:[/bold]")
                # Indent remediation code
                for line in finding.remediation.strip().split('\n'):
                    console.print(f"      [dim]{escape(line)}[/dim]")

            # Guideline link — scheme-validated: a javascript: guideline must
            # not become a clickable link in terminal markup either, and Rich
            # [link=...] interpolates the value raw (no markup escaping).
            guideline = safe_guideline(finding.guideline)
            if guideline:
                console.print(f"\n    [link={escape(guideline)}]→ Documentation[/link]")

    # Footer
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]\n")
