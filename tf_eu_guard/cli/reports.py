"""Report-format dispatch for the command-line interface."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from tf_eu_guard import __version__
from tf_eu_guard.cli.paths import find_repository_root, sarif_scan_root
from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.auditor_report import generate_auditor_report
from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report
from tf_eu_guard.reporting.dev_report import generate_dev_report
from tf_eu_guard.reporting.sarif_report import build_sarif
from tf_eu_guard.reporting.security_report import generate_security_report
from tf_eu_guard.reporting.sorting import sort_findings, sorted_articles


def render_json_report(
    findings: list[EnrichedFinding], unmapped: list[dict[str, Any]]
) -> None:
    """Print the mapped findings as the JSON report."""
    output = [
        {
            "check_id": finding.check_id,
            "severity": finding.severity.value,
            "resource": finding.resource,
            "file_path": finding.file_path,
            "articles": [
                {"framework": article.framework.value, "article": article.article}
                for article in sorted_articles(finding)
            ],
        }
        for finding in sort_findings(findings)
    ]
    print(json.dumps(output, indent=2, sort_keys=True))
    # Machine-readable stdout stays a pure findings array; the unmapped count
    # goes to stderr so pipelines parsing stdout are unaffected while humans
    # still see it.
    if unmapped:
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) not shown above "
            f"(no current EU regulatory mapping).",
            file=sys.stderr,
        )


def render_sarif_report(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
) -> None:
    """Render SARIF to stdout or the requested output file."""
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"
    scan_root = sarif_scan_root(args.path, args.iac_type)
    document = build_sarif(
        findings,
        unmapped=unmapped,
        version=__version__,
        target=target,
        scan_root=scan_root,
        repository_root=find_repository_root(scan_root),
    )
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"SARIF report written to {args.output_file} "
            f"({len(findings)} mapped, {len(unmapped)} unmapped findings)."
        )
        return

    print(json.dumps(document, indent=2, sort_keys=True))
    # Same stdout-purity policy as --output json: the unmapped note goes to
    # stderr.
    if unmapped:
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) included "
            f"as note-level results with mapped=false.",
            file=sys.stderr,
        )


def render_html_reports(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
) -> None:
    """Render one or all HTML report formats."""
    now = datetime.now(UTC)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    # Microseconds sort chronologically; the random suffix prevents concurrent
    # scans in the same clock tick from sharing a name.
    timestamp_suffix = f"{now:%Y%m%dT%H%M%S%fZ}_{uuid4().hex}"
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"

    # Default to reports/ directory. Unique names prevent scans running
    # concurrently from overwriting one another.
    output_directory = args.output_dir or Path("reports")
    output_directory.mkdir(parents=True, exist_ok=True)

    report_generators = {
        "dev": (f"dev_report_{timestamp_suffix}.html", generate_dev_html_report),
        "security": (f"scan_report_{timestamp_suffix}.html", generate_security_report),
        "auditor": (f"auditor_report_{timestamp_suffix}.html", generate_auditor_report),
    }
    report_kinds = (
        ["dev", "security", "auditor"]
        if args.output == "all"
        else [args.output]
    )

    written_paths = []
    for report_kind in report_kinds:
        default_name, generator = report_generators[report_kind]
        # --output-file only overrides the destination for a single format.
        if args.output == "all":
            output_path = output_directory / default_name
        else:
            output_path = args.output_file or (output_directory / default_name)
        # Keep --output-file behavior consistent across report formats: custom
        # HTML destinations may point into a directory that does not exist yet.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        generator(
            findings,
            target=target,
            timestamp=timestamp,
            version=__version__,
            output_path=output_path,
            unmapped_count=len(unmapped),
        )
        written_paths.append(output_path)

    label = (
        "Reports"
        if len(written_paths) > 1
        else f"{args.output.capitalize()} report"
    )
    print(f"{label} written ({len(findings)} findings):")
    for output_path in written_paths:
        print(f"  {output_path}")


def render_scan_output(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
) -> None:
    """Dispatch a scan result to the selected report format."""
    if args.output == "dev":
        generate_dev_report(findings, unmapped_count=len(unmapped))
    elif args.output == "json":
        render_json_report(findings, unmapped)
    elif args.output == "sarif":
        render_sarif_report(args, findings, unmapped)
    elif args.output in ("security", "auditor", "all"):
        render_html_reports(args, findings, unmapped)
