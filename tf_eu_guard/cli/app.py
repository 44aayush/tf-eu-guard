"""Command-line orchestration for tf-eu-guard."""

from pathlib import Path

from tf_eu_guard import __version__
from tf_eu_guard.cli.errors import OutputWriteError, handle_scan_error
from tf_eu_guard.cli.gating import apply_scan_gate
from tf_eu_guard.cli.parser import build_parser
from tf_eu_guard.cli.pipeline import filter_findings_by_framework, load_scan_findings
from tf_eu_guard.cli.reports import render_scan_output
from tf_eu_guard.constants import EXIT_INVALID_INPUT, EXIT_OK


def main(registry_path: Path | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "version":
        print(f"tf-eu-guard version {__version__}")
        return EXIT_OK

    if args.command != "scan":
        return EXIT_INVALID_INPUT

    if args.residency_policy == "custom" and not args.allowed_regions:
        parser.error("--residency-policy custom requires --allowed-regions")
    if args.residency_policy != "custom" and args.allowed_regions:
        parser.error("--allowed-regions is only valid with --residency-policy custom")

    # Default to the current working directory when no path is given (the
    # pre-commit hook invokes the CLI with no positional arguments).
    if not args.path and not args.checkov_json:
        args.path = Path(".")

    try:
        loaded = load_scan_findings(args, registry_path)
        findings = filter_findings_by_framework(loaded.findings, args.framework)
        suppressed = filter_findings_by_framework(loaded.suppressed, args.framework)
        try:
            render_scan_output(
                args,
                findings,
                loaded.unmapped,
                suppressed=suppressed,
                suppressed_unmapped=loaded.suppressed_unmapped,
                checkov_version=loaded.checkov_version,
            )
        except (OSError, UnicodeEncodeError) as error:
            raise OutputWriteError(f"Cannot write report output: {error}") from error
        return apply_scan_gate(args, findings, loaded.unmapped, suppressed=suppressed)
    except Exception as error:
        return handle_scan_error(error)
