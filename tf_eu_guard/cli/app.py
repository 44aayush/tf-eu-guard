"""Command-line orchestration for tf-eu-guard."""

from pathlib import Path

from tf_eu_guard import __version__
from tf_eu_guard.cli.errors import handle_scan_error
from tf_eu_guard.cli.gating import apply_scan_gate
from tf_eu_guard.cli.parser import build_parser
from tf_eu_guard.cli.pipeline import filter_findings_by_framework, load_scan_findings
from tf_eu_guard.cli.reports import render_scan_output
from tf_eu_guard.constants import EXIT_INVALID_INPUT, EXIT_OK


def main(registry_path: Path | None = None) -> int:
    """Run the command-line interface."""
    args = build_parser().parse_args()

    if args.command == "version":
        print(f"tf-eu-guard version {__version__}")
        return EXIT_OK

    if args.command != "scan":
        return EXIT_INVALID_INPUT

    # Default to the current working directory when no path is given (the
    # pre-commit hook invokes the CLI with no positional arguments).
    if not args.path and not args.checkov_json:
        args.path = Path(".")

    try:
        findings, unmapped = load_scan_findings(args, registry_path)
        findings = filter_findings_by_framework(findings, args.framework)
        render_scan_output(args, findings, unmapped)
        return apply_scan_gate(args, findings, unmapped)
    except Exception as error:
        return handle_scan_error(error)
