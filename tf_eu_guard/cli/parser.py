"""Argument parser construction for the CLI."""

import argparse
from pathlib import Path

from tf_eu_guard.constants import (
    FRAMEWORK_FILTERS,
    OUTPUT_FORMATS,
    SUPPORTED_IAC_TYPES,
)
from tf_eu_guard.models import Severity


def fail_on_severity_arg(value: str) -> str | None:
    """Parse ``--fail-on-severity`` while allowing an empty disabled value."""
    if value == "":
        return None
    if value not in {severity.value for severity in Severity}:
        raise argparse.ArgumentError(
            None,
            f"invalid choice: {value!r} "
            f"(choose from CRITICAL, HIGH, MEDIUM, LOW, INFO, or '' to disable)",
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser used by :func:`tf_eu_guard.cli.main`."""
    parser = argparse.ArgumentParser(
        prog="tf-eu-guard",
        description="EU compliance security linter for Terraform (source, plan JSON) "
        "and Kubernetes (NIS2 + GDPR)",
    )
    parser.add_argument(
        "command",
        choices=["scan", "version"],
        help="Command to execute",
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Path to IaC directory to scan (default: the current working "
        "directory, so the pre-commit hook can invoke the CLI with no "
        "positional arguments)",
    )
    parser.add_argument(
        "--iac-type",
        choices=list(SUPPORTED_IAC_TYPES),
        default="terraform",
        help="IaC language to scan (default: terraform). Passed to Checkov's "
        "--framework flag. NOTE: unrelated to --framework below, which "
        "selects the compliance regime to REPORT (NIS2/GDPR). "
        "'terraform_plan' scans a 'terraform show -json' plan file "
        "(pass its path as PATH), not a directory.",
    )
    parser.add_argument(
        "--output",
        choices=list(OUTPUT_FORMATS),
        default="dev",
        help="Report format (default: dev). 'all' writes the dev, security and "
        "auditor HTML files together (see --output-dir). 'sarif' writes a "
        "SARIF 2.1.0 document (GitHub Code Scanning format) to stdout, or "
        "to --output-file when given.",
    )
    parser.add_argument(
        "--framework",
        choices=list(FRAMEWORK_FILTERS),
        default="all",
        help="Compliance framework filter (default: all) — which regulatory "
        "regime to report on. Unrelated to --iac-type (what to scan).",
    )
    parser.add_argument(
        "--checkov-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="Use a pre-generated Checkov JSON result (NOT a raw Terraform plan "
        "file) instead of running Checkov. Use '-' to read from stdin. "
        "PATH becomes optional when this is set.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="For --output security|auditor|sarif, write the single report here "
        "(HTML defaults to reports/scan_report_<timestamp>.html or "
        "reports/auditor_report_<timestamp>.html; sarif: stdout by "
        "default). Ignored for dev, json and all.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for HTML report output (default: reports/; "
        "created if missing). For --output all, the three HTML files are "
        "written here with timestamped names.",
    )

    parser.add_argument(
        "--fail-on-severity",
        type=fail_on_severity_arg,
        default=None,
        metavar="SEVERITY",
        help="Exit with code 1 if any finding is at or above this severity "
        "(CRITICAL, HIGH, MEDIUM, LOW, INFO — for CI/CD gating). Default: "
        "disabled (exit 0 unless an error occurs). An empty value also "
        "disables gating (the GitHub Action passes its cleared input "
        "through verbatim). "
        "Only MAPPED findings are considered: severity is authored in the "
        "mapping registry, so unmapped Checkov findings have no severity "
        "to compare and never trip the gate (they are reported for "
        "visibility instead).",
    )
    parser.add_argument(
        "--fail-on-any",
        action="store_true",
        help="Exit with code 1 if any finding exists, regardless of severity. "
        "Like --fail-on-severity, considers only MAPPED findings "
        "(unmapped Checkov findings are surfaced in reports but do not "
        "fail the gate).",
    )
    return parser
