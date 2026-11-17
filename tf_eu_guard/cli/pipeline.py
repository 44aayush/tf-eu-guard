"""Scan acquisition and framework filtering for the CLI."""

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tf_eu_guard.checkov_runner as checkov_runner
from tf_eu_guard.checkov.json import allow_partial_results, checkov_version_of
from tf_eu_guard.cli.paths import scope_risk_text
from tf_eu_guard.constants import DEFAULT_CHECKOV_TIMEOUT
from tf_eu_guard.mapping.loader import load_registry, split_findings
from tf_eu_guard.models import EnrichedFinding, Framework
from tf_eu_guard.residency import DEFAULT_POLICY, residency_env


@dataclass
class ScanFindings:
    """Findings of one scan, split by registry coverage and suppression."""

    findings: list[EnrichedFinding]
    unmapped: list[dict[str, Any]]
    suppressed: list[EnrichedFinding] = field(default_factory=list)
    suppressed_unmapped: list[dict[str, Any]] = field(default_factory=list)
    checkov_version: str | None = None


def load_scan_findings(
    args: argparse.Namespace,
    registry_path: Path | None,
) -> ScanFindings:
    """Run or load Checkov, then split findings by registry coverage.

    Active findings come from ``failed_checks``; findings suppressed by inline
    ``checkov:skip`` comments come from ``skipped_checks`` and stay separate.
    """
    policy = getattr(args, "residency_policy", DEFAULT_POLICY)
    allowed = getattr(args, "allowed_regions", None)
    if args.checkov_json:
        if policy != DEFAULT_POLICY or allowed:
            print(
                "Warning: --residency-policy/--allowed-regions are ignored with "
                "--checkov-json; the results were computed with the policy in "
                "effect when Checkov ran.",
                file=sys.stderr,
            )
    with allow_partial_results(getattr(args, "allow_partial", False)):
        if args.checkov_json:
            checkov_output = checkov_runner.load_checkov_json(args.checkov_json, args.iac_type)
        else:
            checkov_output = checkov_runner.run_checkov(
                args.path,
                args.iac_type,
                residency_env(policy, allowed),
                exclude=getattr(args, "exclude", None) or (),
                online=getattr(args, "online", False),
                timeout=getattr(args, "timeout", DEFAULT_CHECKOV_TIMEOUT),
            )
    findings = checkov_runner.extract_failed_checks(checkov_output)
    skipped = checkov_runner.extract_skipped_checks(checkov_output)

    registry_dir = registry_path or (Path(__file__).parent.parent / "mapping")
    registry = load_registry(registry_dir)
    active, unmapped = split_findings(findings, registry)
    suppressed, suppressed_unmapped = split_findings(skipped, registry)
    return ScanFindings(
        active, unmapped, suppressed, suppressed_unmapped, checkov_version_of(checkov_output)
    )


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
            article for article in finding.articles if article.framework == target_framework
        ]
        if finding.articles:
            finding.risk_explanation = scope_risk_text(
                finding.risk_explanation, target_framework.value
            )
            filtered_findings.append(finding)
    return filtered_findings
