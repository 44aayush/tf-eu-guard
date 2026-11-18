"""Command-line orchestration for tf-eu-guard."""

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from tf_eu_guard import __version__
from tf_eu_guard.cli.commands import run_subcommand
from tf_eu_guard.cli.errors import OutputWriteError, handle_scan_error
from tf_eu_guard.cli.gating import apply_scan_gate
from tf_eu_guard.cli.parser import apply_config, build_parser
from tf_eu_guard.cli.pipeline import (
    ScanFindings,
    filter_findings_by_framework,
    load_scan_findings,
)
from tf_eu_guard.cli.reports import (
    check_evidence_dir,
    render_markdown_csv_outputs,
    render_scan_output,
    write_evidence_bundle,
)
from tf_eu_guard.config import ConfigError
from tf_eu_guard.constants import EXIT_INVALID_INPUT, EXIT_OK
from tf_eu_guard.mapping.coverage import evaluate_requirements
from tf_eu_guard.provenance import build_provenance, needs_provenance

ScanResult = ScanFindings


def prepare_scan_args(argv: list[str]) -> argparse.Namespace:
    """Config merge, parse, list concatenation, residency validation, path default.

    Shared by the CLI and ``tf_eu_guard.scan`` so they cannot drift. Raises
    ``ConfigError`` for a bad config and ``SystemExit`` (argparse) for bad arguments.
    """
    parser = build_parser()
    config_lists = apply_config(parser, argv)
    args = parser.parse_args(argv)
    if args.command != "scan":
        return args

    for dest, values in config_lists.items():
        setattr(args, dest, [*values, *getattr(args, dest)])

    if args.residency_policy == "custom" and not args.allowed_regions:
        parser.error("--residency-policy custom requires --allowed-regions")
    if args.residency_policy != "custom" and args.allowed_regions:
        parser.error("--allowed-regions is only valid with --residency-policy custom")

    # Default to the current working directory when no path is given (the
    # pre-commit hook invokes the CLI with no positional arguments).
    if not args.path and not args.checkov_json:
        args.path = Path(".")
    return args


def run_scan(
    args: argparse.Namespace,
    registry_path: Path | None = None,
    *,
    with_provenance: bool | None = None,
) -> ScanResult:
    """Load, filter and evaluate a scan; does not render or gate; prints waiver and baseline counts to stderr.

    Provenance (which runs git) is built only when an output needs it, unless forced.
    """
    if with_provenance is None:
        with_provenance = needs_provenance(args)
    loaded = load_scan_findings(args, registry_path)
    # Rows follow --framework: all 15 for 'all', otherwise that framework only.
    # Known findings still fail the check; --changed-since does not alter the matrix.
    failed, skipped, matrix_waived = loaded.matrix_inputs or (
        [*loaded.findings, *loaded.baselined],
        loaded.suppressed,
        loaded.waived,
    )
    requirements = (
        evaluate_requirements(
            loaded.registry.mappings,
            loaded.passed,
            failed,
            skipped,
            waived=matrix_waived,
        )
        if loaded.registry
        else []
    )
    if requirements and args.framework != "all":
        requirements = [
            r for r in requirements if r.requirement.framework.value.lower() == args.framework
        ]
    waived = filter_findings_by_framework(loaded.waived, args.framework)
    baselined = filter_findings_by_framework(loaded.baselined, args.framework)
    if waived:
        print(f"{len(waived)} finding(s) waived by {loaded.waiver_path}", file=sys.stderr)
    if baselined:
        print(
            f"{len(baselined)} finding(s) match the baseline {loaded.baseline_origin}",
            file=sys.stderr,
        )
    return replace(
        loaded,
        findings=filter_findings_by_framework(loaded.findings, args.framework),
        suppressed=filter_findings_by_framework(loaded.suppressed, args.framework),
        waived=waived,
        baselined=baselined,
        requirements=requirements,
        provenance=build_provenance(args, loaded, loaded.checkov_summary)
        if with_provenance
        else {},
    )


def main(registry_path: Path | None = None) -> int:
    """Run the command-line interface."""
    handled = run_subcommand(sys.argv[1:], registry_path)
    if handled is not None:
        return handled

    try:
        args = prepare_scan_args(sys.argv[1:])
    except ConfigError as error:
        return handle_scan_error(error)

    if args.command == "version":
        print(f"tf-eu-guard version {__version__}")
        return EXIT_OK

    if args.command != "scan":
        return EXIT_INVALID_INPUT

    try:
        if args.evidence_dir:
            check_evidence_dir(args.evidence_dir)
        shown = run_scan(args, registry_path)
        requirements = shown.requirements or None
        try:
            render_scan_output(
                args,
                shown.findings,
                shown.unmapped,
                suppressed=shown.suppressed,
                suppressed_unmapped=shown.suppressed_unmapped,
                checkov_version=shown.checkov_version,
                requirements=requirements,
                registry=shown.registry,
                waived=shown.waived,
                weakening_settings=shown.weakening_settings,
                # None tells SARIF that no baseline was used (no baselineState).
                baselined=shown.baselined if args.baseline else None,
                provenance=shown.provenance,
            )
            render_markdown_csv_outputs(args, shown)
            if args.evidence_dir:
                write_evidence_bundle(args, shown, requirements, shown.provenance)
        except (OSError, UnicodeEncodeError) as error:
            raise OutputWriteError(f"Cannot write report output: {error}") from error
        return apply_scan_gate(args, shown.findings, shown.unmapped, suppressed=shown.suppressed)
    except Exception as error:
        return handle_scan_error(error)
