"""Scan acquisition and framework filtering for the CLI."""

import argparse
from pathlib import Path
from typing import Any

import tf_eu_guard.checkov_runner as checkov_runner
from tf_eu_guard.cli.paths import scope_risk_text
from tf_eu_guard.mapping.loader import load_registry, split_findings
from tf_eu_guard.models import EnrichedFinding, Framework


def load_scan_findings(
    args: argparse.Namespace,
    registry_path: Path | None,
) -> tuple[list[EnrichedFinding], list[dict[str, Any]]]:
    """Run or load Checkov, then split findings by registry coverage."""
    if args.checkov_json:
        checkov_output = checkov_runner.load_checkov_json(args.checkov_json, args.iac_type)
    else:
        checkov_output = checkov_runner.run_checkov(args.path, args.iac_type)
    findings = checkov_runner.extract_failed_checks(checkov_output)

    registry_dir = registry_path or (Path(__file__).parent.parent / "mapping")
    registry = load_registry(registry_dir)
    return split_findings(findings, registry)


def filter_findings_by_framework(
    findings: list[EnrichedFinding],
    framework_name: str,
) -> list[EnrichedFinding]:
    """Keep only articles in the selected framework and scope risk text."""
    if framework_name == "all":
        return findings

    target_framework = Framework(framework_name.upper())
    filtered_findings: list[EnrichedFinding] = []
    for finding in findings:
        finding.articles = [
            article for article in finding.articles
            if article.framework == target_framework
        ]
        if finding.articles:
            finding.risk_explanation = scope_risk_text(
                finding.risk_explanation, target_framework.value
            )
            filtered_findings.append(finding)
    return filtered_findings
