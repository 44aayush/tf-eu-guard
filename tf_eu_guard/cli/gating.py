"""CI finding-gate helpers for the command-line interface."""

import argparse
import sys
from typing import Any

from tf_eu_guard.constants import EXIT_FINDINGS, EXIT_OK
from tf_eu_guard.models import EnrichedFinding, Severity

SEVERITIES_LOW_TO_HIGH = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def find_gate_failures(
    args: argparse.Namespace, findings: list[EnrichedFinding]
) -> list[EnrichedFinding]:
    """Return mapped findings that satisfy the configured CI gate."""
    if args.fail_on_any:
        return list(findings)
    if not args.fail_on_severity:
        return []

    threshold = Severity(args.fail_on_severity)
    threshold_rank = SEVERITIES_LOW_TO_HIGH.index(threshold)
    return [
        finding
        for finding in findings
        if SEVERITIES_LOW_TO_HIGH.index(finding.severity) >= threshold_rank
    ]


def apply_scan_gate(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
) -> int:
    """Print gate messages and return the scan's findings status code."""
    failing_findings = find_gate_failures(args, findings)
    if failing_findings:
        print(
            f"Fail: {len(failing_findings)} finding(s) at or above threshold "
            f"({args.fail_on_severity or 'ANY'}) — see report above.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS

    # Unmapped Checkov findings never affect the gate because severity is
    # registry-authored. Surface that policy in CI output when a gate is used.
    if unmapped and (args.fail_on_any or args.fail_on_severity):
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) were reported but "
            f"do not affect this gate (no current EU regulatory mapping).",
            file=sys.stderr,
        )
    return EXIT_OK
