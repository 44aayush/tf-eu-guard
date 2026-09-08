"""Developer-focused terminal report."""

from pathlib import Path

from rich.console import Console

from tf_eu_guard.models import EnrichedFinding, ScanReport
from tf_eu_guard.reporting._html_common import safe_guideline
from tf_eu_guard.reporting.base import BaseReporter
from tf_eu_guard.reporting.styles import SEVERITY_COLOR_TERMINAL, SEVERITY_ORDER


def _line_ref(finding: EnrichedFinding) -> str | None:
    """Line reference for a finding, or ``None`` when none is meaningful.

    Checkov reports ``[0, 0]`` for frameworks with no real line anchor — e.g.
    terraform_plan JSON or some Kubernetes findings — in which case printing
    ``Lines: 0-0`` would be misleading.
    """
    lr = finding.file_line_range or []
    if len(lr) >= 2 and (lr[0] or lr[1]):
        return f"{lr[0]}-{lr[1]}"
    if len(lr) == 1 and lr[0]:
        return str(lr[0])
    return None


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

        for file_path, findings in sorted(by_file.items()):
            output.append(f"\n[bold cyan]{file_path}[/bold cyan]")

            # Sort findings by severity within each file (unknown severities last)
            sorted_findings = sorted(
                findings,
                key=lambda f: SEVERITY_ORDER.index(f.severity)
                if f.severity in SEVERITY_ORDER
                else len(SEVERITY_ORDER),
            )

            for finding in sorted_findings:
                severity_color = SEVERITY_COLOR_TERMINAL[finding.severity]

                output.append(f"\n  [{severity_color}]●[/{severity_color}] {finding.check_id}: {finding.check_name}")
                output.append(f"    Resource: {finding.resource}")
                line_ref = _line_ref(finding)
                if line_ref:
                    output.append(f"    Lines: {line_ref}")
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
    severity_counts = {}
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

    # Group by file
    by_file: dict[str, list[EnrichedFinding]] = {}
    for finding in findings:
        if finding.file_path not in by_file:
            by_file[finding.file_path] = []
        by_file[finding.file_path].append(finding)

    # Display findings
    for file_path, file_findings in sorted(by_file.items()):
        console.print(f"\n[bold cyan]File: {file_path}[/bold cyan]")

        # Sort by severity (unknown severities last)
        sorted_findings = sorted(
            file_findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity)
            if f.severity in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
        )

        for finding in sorted_findings:
            # Severity badge
            severity_color = SEVERITY_COLOR_TERMINAL[finding.severity]

            console.print(f"\n  [{severity_color}]●[/{severity_color}] [bold]{finding.check_id}[/bold]: {finding.check_name}")
            console.print(f"    [dim]Resource:[/dim] {finding.resource}")
            line_ref = _line_ref(finding)
            if line_ref:
                console.print(f"    [dim]Lines:[/dim] {line_ref}")
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

            # Guideline link — scheme-validated: a javascript: guideline must
            # not become a clickable link in terminal markup either, and Rich
            # [link=...] interpolates the value raw (no markup escaping).
            guideline = safe_guideline(finding.guideline)
            if guideline:
                console.print(f"\n    [link={guideline}]→ Documentation[/link]")

    # Footer
    console.print("\n[bold]═══════════════════════════════════════════════════[/bold]\n")
