"""Developer-focused terminal report."""

from pathlib import Path

from rich.console import Console

from tf_eu_guard.models import EnrichedFinding, ScanReport, Severity
from tf_eu_guard.reporting.base import BaseReporter


class DevReporter(BaseReporter):
    """Terminal-first report optimized for developers."""

    def __init__(self):
        self.console = Console()

    def generate(self, report: ScanReport, output_path: Path | None = None) -> str:
        """Generate developer-focused terminal report."""
        # Group findings by file for easier navigation
        by_file: dict[str, list] = {}
        for finding in report.findings:
            if finding.file_path not in by_file:
                by_file[finding.file_path] = []
            by_file[finding.file_path].append(finding)

        output = []
        output.append("\n[bold]tf-eu-guard scan results[/bold]")
        output.append(f"Target: {report.target_path}")
        output.append(f"Timestamp: {report.scan_timestamp}")
        output.append(f"\nFindings: {report.total_failed} failed / {report.total_checks_run} total\n")

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for file_path, findings in sorted(by_file.items()):
            output.append(f"\n[bold cyan]{file_path}[/bold cyan]")

            # Sort findings by severity within each file
            sorted_findings = sorted(
                findings,
                key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
            )

            for finding in sorted_findings:
                severity_color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                }[finding.severity]

                output.append(f"\n  [{severity_color}]●[/{severity_color}] {finding.check_id}: {finding.check_name}")
                output.append(f"    Resource: {finding.resource}")
                output.append(f"    Lines: {finding.file_line_range[0]}-{finding.file_line_range[1]}")
                output.append(f"    Severity: [{severity_color}]{finding.severity.value}[/{severity_color}]")

                if finding.articles:
                    articles_str = ", ".join(f"{a.framework.value} {a.article}" for a in finding.articles)
                    output.append(f"    Compliance: {articles_str}")

                output.append(f"\n    [dim]{finding.risk_explanation}[/dim]")

                if finding.remediation:
                    output.append("\n    [bold]Fix:[/bold]")
                    output.append(f"    {finding.remediation}")

        report_text = "\n".join(output)

        if output_path:
            with open(output_path, "w") as f:
                # Strip Rich markup for file output
                import re
                plain_text = re.sub(r'\[.*?\]', '', report_text)
                f.write(plain_text)

        return report_text


def generate_dev_report(findings: list[EnrichedFinding]) -> None:
    """
    Generate and print developer-focused terminal report.

    Args:
        findings: List of enriched findings with compliance mappings
    """
    console = Console()

    if not findings:
        console.print("\n[green]✓ No compliance findings![/green]\n")
        return

    # Header
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]")
    console.print("[bold]  tf-eu-guard: EU Compliance Scan Report[/bold]")
    console.print("[bold]═══════════════════════════════════════════════════[/bold]\n")

    # Summary
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    console.print(f"[bold]Total Findings:[/bold] {len(findings)}")
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if severity in severity_counts:
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}[severity.value]
            console.print(f"  [{color}]●[/{color}] {severity.value}: {severity_counts[severity]}")
    console.print()

    # Group by file
    by_file: dict[str, list[EnrichedFinding]] = {}
    for finding in findings:
        if finding.file_path not in by_file:
            by_file[finding.file_path] = []
        by_file[finding.file_path].append(finding)

    # Display findings
    for file_path, file_findings in sorted(by_file.items()):
        console.print(f"\n[bold cyan]File: {file_path}[/bold cyan]")

        # Sort by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        sorted_findings = sorted(
            file_findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
        )

        for finding in sorted_findings:
            # Severity badge
            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
            }[finding.severity]

            console.print(f"\n  [{severity_color}]●[/{severity_color}] [bold]{finding.check_id}[/bold]: {finding.check_name}")
            console.print(f"    [dim]Resource:[/dim] {finding.resource}")
            console.print(f"    [dim]Lines:[/dim] {finding.file_line_range[0]}-{finding.file_line_range[1]}")
            console.print(f"    [dim]Severity:[/dim] [{severity_color}]{finding.severity.value}[/{severity_color}]")

            # Compliance articles
            if finding.articles:
                articles_str = ", ".join(
                    f"[bold]{a.framework.value}[/bold] {a.article}"
                    for a in finding.articles
                )
                console.print(f"    [dim]Compliance:[/dim] {articles_str}")

            # Risk explanation
            console.print(f"\n    [italic]{finding.risk_explanation}[/italic]")

            # Remediation
            if finding.remediation:
                console.print("\n    [bold]Remediation:[/bold]")
                # Indent remediation code
                for line in finding.remediation.strip().split('\n'):
                    console.print(f"      [dim]{line}[/dim]")

            # Guideline link
            if finding.guideline:
                console.print(f"\n    [link={finding.guideline}]→ Documentation[/link]")

    # Footer
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]\n")
