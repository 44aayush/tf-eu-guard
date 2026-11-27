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


def _unmapped_meets_gate(args: argparse.Namespace, level: str) -> bool:
    """Return whether unmapped findings counted at ``level`` trip the severity gate."""
    if args.fail_on_any:
        return True
    if not args.fail_on_severity:
        return False
    rank = SEVERITIES_LOW_TO_HIGH.index
    return rank(Severity(level)) >= rank(Severity(args.fail_on_severity))


def apply_scan_gate(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
) -> int:
    """Print gate messages and return the scan's findings status code.

    ``findings`` are the active findings only; suppressed ones never count
    toward ``--fail-on-severity`` / ``--fail-on-any`` and trip the gate only
    through ``--fail-on-suppressed``.
    """
    failing_findings = find_gate_failures(args, findings)
    gate_failed = False
    if failing_findings:
        print(
            f"Fail: {len(failing_findings)} finding(s) at or above threshold "
            f"({'ANY' if args.fail_on_any else args.fail_on_severity}) — see report above.",
            file=sys.stderr,
        )
        gate_failed = True

    if getattr(args, "fail_on_suppressed", False) and suppressed:
        print(
            f"Fail: {len(suppressed)} mapped finding(s) suppressed by inline "
            f"Checkov comments (--fail-on-suppressed) — see report above.",
            file=sys.stderr,
        )
        gate_failed = True

    unmapped_level = getattr(args, "unmapped_severity", None)
    if unmapped and unmapped_level and _unmapped_meets_gate(args, unmapped_level):
        print(
            f"Fail: {len(unmapped)} unmapped Checkov finding(s) counted as {unmapped_level} "
            f"(--unmapped-severity) at or above threshold "
            f"({'ANY' if args.fail_on_any else args.fail_on_severity}).",
            file=sys.stderr,
        )
        gate_failed = True

    if getattr(args, "fail_on_unmapped", False) and unmapped:
        print(
            f"Fail: {len(unmapped)} unmapped Checkov finding(s) (--fail-on-unmapped)",
            file=sys.stderr,
        )
        gate_failed = True

    if gate_failed:
        return EXIT_FINDINGS

    # Unmapped Checkov findings do not affect the gate unless --unmapped-severity
    # counts them, because severity is registry-authored. Surface that policy in
    # CI output when a gate is used.
    if (
        unmapped
        and (args.fail_on_any or args.fail_on_severity)
        and not getattr(args, "fail_on_unmapped", False)
    ):
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) were reported but "
            f"do not affect this gate (no current EU regulatory mapping).",
            file=sys.stderr,
        )
    return EXIT_OK
