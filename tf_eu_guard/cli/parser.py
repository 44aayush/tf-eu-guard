"""Argument parser construction for the CLI."""

import argparse
import math
import sys
from pathlib import Path
from typing import Any

from tf_eu_guard import __version__
from tf_eu_guard.config import find_config, load_config
from tf_eu_guard.constants import (
    DEFAULT_CHECKOV_TIMEOUT,
    FRAMEWORK_FILTERS,
    OUTPUT_FORMATS,
    SUPPORTED_IAC_TYPES,
)
from tf_eu_guard.models import Severity
from tf_eu_guard.reporting.untrusted import sanitize
from tf_eu_guard.residency import DEFAULT_POLICY, RESIDENCY_POLICIES, parse_allowed_regions


def fail_on_severity_arg(value: str) -> str | None:
    """Parse ``--fail-on-severity`` while allowing an empty disabled value."""
    if value == "":
        return None
    normalised = value.strip().upper()
    if normalised not in {severity.value for severity in Severity}:
        raise argparse.ArgumentTypeError(
            f"invalid choice: {value!r} "
            f"(choose from CRITICAL, HIGH, MEDIUM, LOW, INFO, or '' to disable)"
        )
    return normalised


def timeout_arg(value: str) -> float:
    """Parse ``--timeout`` as a non-negative number of seconds (0 disables)."""
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number of seconds: {value!r}") from None
    if not math.isfinite(seconds) or seconds < 0:
        raise argparse.ArgumentTypeError(f"must be a finite number >= 0, got {value!r}")
    return seconds


def allowed_regions_arg(value: str) -> tuple[str, ...]:
    """Parse ``--allowed-regions`` into normalised region codes."""
    try:
        return parse_allowed_regions(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser used by :func:`tf_eu_guard.cli.main`."""
    parser = argparse.ArgumentParser(
        prog="tf-eu-guard",
        description="EU compliance security linter for Terraform (source, plan JSON) "
        "and Kubernetes (NIS2 + GDPR)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"tf-eu-guard {__version__}",
        help="Print the version and exit (same as the 'version' command).",
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
        "to --output-file when given. 'markdown' writes a summary and 'csv' one "
        "row per finding and article, to stdout or --output-file.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="Also write the Markdown summary here, whatever --output is "
        "(UTF-8; parent directory created).",
    )
    parser.add_argument(
        "--counts-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="Also write key=value counts (critical, high, medium, low, info, "
        "unmapped, suppressed, waived, baselined, total), one per line in "
        "GitHub $GITHUB_OUTPUT format.",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Also write an evidence bundle to DIR (must not exist or be empty): "
        "dev.html, security.html, auditor.html, report.json (object format), "
        "report.sarif, summary.md and manifest.json (provenance plus a SHA-256 "
        "per file). Independent of --output.",
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
        "--exclude",
        "--skip-path",
        dest="exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Skip files/directories whose absolute path matches PATTERN "
        "(repeatable). Same semantics as Checkov's --skip-path: PATTERN is "
        "a Python regular expression searched in the full path (a pattern "
        "starting with a single '.' is taken literally), and any path "
        "containing PATTERN as plain text also matches, so 'tests/fixtures' "
        "works. Also honoured by tf-eu-guard's symlink and *.tf.json checks. "
        "Ignored with --checkov-json and terraform_plan.",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Let Checkov download guideline metadata from the Prisma Cloud "
        "platform (adds 'Documentation' links; makes one HTTPS request per "
        "scan). Off by default: Checkov runs with --skip-download. Platform "
        "API keys (BC_*, PRISMA_*) are always removed from Checkov's "
        "environment, even with --online; no results are uploaded.",
    )
    parser.add_argument(
        "--timeout",
        type=timeout_arg,
        default=DEFAULT_CHECKOV_TIMEOUT,
        metavar="SECONDS",
        help="Kill the Checkov subprocess and exit 3 if it runs longer than "
        f"SECONDS (default: {DEFAULT_CHECKOV_TIMEOUT}; 0 disables the limit). "
        "Ignored with --checkov-json.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="For --output security|auditor|sarif|json|markdown|csv, write the single report "
        "here (UTF-8; HTML defaults to reports/scan_report_<timestamp>.html or "
        "reports/auditor_report_<timestamp>.html; sarif and json: stdout by "
        "default). Ignored for dev and all.",
    )
    parser.add_argument(
        "--json-format",
        choices=("array", "object"),
        default="array",
        help="Layout of --output json (default: array). 'array' is the legacy "
        "bare list of findings and is deprecated: the default changes to "
        "'object' in a future release. 'object' is the versioned document "
        "(schema_version, tool, checkov_version, scan, summary, findings, "
        "unmapped) with line ranges, check names, risk text and remediation.",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Continue, with a stderr warning, when Checkov reports parsing "
        "errors. By default parsing errors fail the scan (source scans and "
        "--checkov-json alike), because files that could not be parsed were "
        "not checked.",
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
        "--residency-policy",
        choices=list(RESIDENCY_POLICIES),
        default=DEFAULT_POLICY,
        help="AWS region residency policy enforced by EUGUARD_POLICY_001/002 "
        "(default: eu-eea). 'eu-eea' allows EU/EEA commercial regions and the "
        "AWS European Sovereign Cloud; 'eusc' allows only the Sovereign Cloud; "
        "'custom' uses --allowed-regions. Ignored with --checkov-json (results "
        "are pre-computed).",
    )
    parser.add_argument(
        "--allowed-regions",
        type=allowed_regions_arg,
        default=None,
        metavar="REGION[,REGION...]",
        help="Comma-separated region allowlist; required with, and only valid "
        "with, --residency-policy custom.",
    )

    parser.add_argument(
        "--var-file",
        dest="var_files",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Terraform variable definitions file passed to Checkov (repeatable, in "
        "order), so values such as a provider region set through var.* resolve. "
        "Only valid with --iac-type terraform; a missing file exits 2.",
    )
    parser.add_argument(
        "--download-external-modules",
        action="store_true",
        help="Let Checkov download registry and Git modules so their resources are "
        "evaluated. Needs network access and fetches third-party code (it does not "
        "work in the GitHub Action, which runs with --network none). Only valid "
        "with --iac-type terraform.",
    )
    parser.add_argument(
        "--secrets",
        action="store_true",
        help="Also run Checkov's secrets framework (hard-coded credentials, CKV_SECRET_*). "
        "Findings are reported by location only; secret values never appear in any report. "
        "With --checkov-json, a secrets element in the file is merged in.",
    )
    parser.add_argument(
        "--registry-dir",
        dest="registry_dirs",
        action="append",
        type=Path,
        default=[],
        metavar="DIR",
        help="Overlay registry directory (repeatable). Every *.yaml file in it is "
        "merged over the bundled registry, sorted by name; later definitions win "
        "per check ID. Overlays may add checks or override bundled severity, "
        "articles and text; each loaded file is reported on stderr.",
    )
    parser.add_argument(
        "--waivers",
        type=Path,
        default=None,
        metavar="FILE",
        help="Reviewed waiver file (YAML). Waived mapped findings leave the gate but "
        "stay listed in every report with owner, reason and expiry; expired waivers "
        "are ignored with a warning. Default: .tf-eu-guard-waivers.yaml in the scan "
        "root (source scans only; not used with --checkov-json). See docs/waivers.md.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="FILE",
        help="Previous JSON report (object or array format). Active mapped findings "
        "already in it (same check, resource and file; line numbers ignored) are "
        "reported as 'Known (in baseline)' and do not trip --fail-on-severity / "
        "--fail-on-any, so only new findings fail CI. Valid with --checkov-json. "
        "Compare two reports with 'tf-eu-guard diff OLD.json NEW.json'.",
    )
    parser.add_argument(
        "--changed-since",
        default=None,
        metavar="REF",
        help="Report only findings in files changed since the Git ref REF (committed "
        "REF...HEAD and staged changes; unstaged and untracked changes are not included), "
        "e.g. origin/main. Findings in other files are hidden and counted on stderr and "
        "in the scan settings; the requirement matrix still reflects every check "
        "evaluated. Not valid with --checkov-json or --iac-type terraform_plan.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="FILE",
        help="Project configuration file (YAML). Default: .tf-eu-guard.yaml in the scan "
        "root (not searched with --checkov-json). CLI flags override it; list keys "
        "(exclude, registry_dirs, var_files) are concatenated. See docs/configuration.md.",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Ignore any project configuration file, discovered or given with --config.",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="Do not read .tf-eu-guard.yaml or .tf-eu-guard-waivers.yaml from the scan root "
        "(files in a pull request are controlled by its author). --config and --waivers "
        "still apply.",
    )
    parser.add_argument(
        "--fail-on-severity",
        type=fail_on_severity_arg,
        default=None,
        metavar="SEVERITY",
        help="Exit with code 1 if any finding is at or above this severity "
        "(CRITICAL, HIGH, MEDIUM, LOW, INFO, case-insensitive — for CI/CD gating). Default: "
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
    parser.add_argument(
        "--fail-on-suppressed",
        action="store_true",
        help="Exit with code 1 if any MAPPED finding was suppressed by an inline "
        "Checkov comment (#checkov:skip=ID:reason in Terraform, "
        "checkov.io/skip annotations in Kubernetes). Suppressed findings are "
        "always listed in every report but never count toward "
        "--fail-on-severity / --fail-on-any. Honors --framework. Unmapped "
        "suppressed checks are reported but do not trip this gate.",
    )
    parser.add_argument(
        "--show-unmapped",
        action="store_true",
        help="List unmapped Checkov findings (check ID, name, resource, file, "
        "lines) in the dev terminal report and the dev, security and auditor "
        "HTML reports instead of only counting them. JSON (object format) and "
        "SARIF always include them.",
    )
    parser.add_argument(
        "--fail-on-unmapped",
        action="store_true",
        help="Exit with code 1 if any active (not inline-suppressed) unmapped "
        "Checkov finding exists. Unmapped findings otherwise never trip the gate.",
    )
    return parser


def apply_config(
    parser: argparse.ArgumentParser, argv: list[str] | None = None
) -> dict[str, list[Any]]:
    """Load the project config and install it as parser defaults (CLI still wins).

    Returns the list-valued settings, which the caller prepends to the CLI's own
    lists after the real parse. ``config_path`` and ``severity_overrides`` become
    attributes of the parsed namespace.
    """
    known, _ = parser.parse_known_args(argv)
    parser.set_defaults(config_path=None, severity_overrides={})
    if known.command != "scan" or known.no_config:
        return {}
    path = known.config
    if path is None and not known.checkov_json:
        found = find_config(known.path or Path("."))
        if known.no_discovery:
            if found is not None:
                print(f"Note: --no-discovery: ignored {sanitize(found)}", file=sys.stderr)
            return {}
        path = found
    if path is None:
        return {}
    values = load_config(path)
    lists: dict[str, list[Any]] = {
        k: values.pop(k) for k in ("exclude", "registry_dirs", "var_files") if k in values
    }
    parser.set_defaults(config_path=path, **values)
    return lists
