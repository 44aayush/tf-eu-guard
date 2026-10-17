"""Checkov runner module — invokes Checkov programmatically."""

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

from tf_eu_guard.constants import SUPPORTED_IAC_TYPES


class CheckovRuntimeError(RuntimeError):
    """Raised when Checkov fails or does not return parseable JSON."""


class CheckovInputError(ValueError):
    """Raised when a user-supplied Checkov JSON path cannot be read."""


def _stderr_tail(stderr: str | None, limit: int = 20) -> str:
    """Return the final stderr lines, keeping runtime errors actionable."""
    lines = (stderr or "").splitlines()
    return "\n".join(lines[-limit:]) or "(no stderr output)"


_CHECKOV_CONFIG_ENV_VARS = (
    "CKV_CHECK",
    "CKV_EVAL_VARS",
    "CKV_EXTERNAL_CHECKS_PUBLIC_KEY",
    "CKV_FRAMEWORK",
    "CKV_NO_FAIL_ON_CRASH",
    "CKV_POLICY_METADATA_FILTER",
    "CKV_POLICY_METADATA_FILTER_EXCEPTION",
    "CKV_SECRETS_SCAN_BLOCK_LIST",
    "CKV_SECRETS_SCAN_ENABLE_ALL",
    "CKV_SECRETS_SCAN_FILE_TYPE",
    "CKV_SKIP_CHECK",
    "CKV_SKIP_RESOURCES_WITHOUT_VIOLATIONS",
    "CKV_VAR_FILE",
    "DOWNLOAD_EXTERNAL_MODULES",
    "EXTERNAL_MODULES_DIR",
)


_CHECKOV_BOOTSTRAP = """
import sys

import checkov.common.util.config_utils as config_utils
import checkov.main as checkov_main


# Checkov 3.3.x discovers .checkov.yml/.checkov.yaml from the scan directory,
# cwd, and HOME. tf-eu-guard owns the checks that are required for its report,
# so user configuration must not be able to remove them silently.
config_utils.get_default_config_paths = lambda argv: []
checkov_main.get_default_config_paths = lambda argv: []

sys.exit(checkov_main.Checkov(sys.argv[1:]).run())
"""


def _trusted_checkov_workdir() -> Path:
    """Return a directory outside the scanned checkout for Checkov's cwd."""
    purelib = Path(sysconfig.get_path("purelib"))
    if purelib.is_dir():
        return purelib
    # This fallback is still package-relative and, unlike the scan target, is
    # controlled by tf-eu-guard. ``-I`` below prevents cwd/PYTHONPATH shadowing.
    return Path(__file__).resolve().parent


def _checkov_environment() -> dict[str, str]:
    """Return an environment without Checkov's user-configurable scan filters."""
    environment = os.environ.copy()
    for name in _CHECKOV_CONFIG_ENV_VARS:
        environment.pop(name, None)
    return environment


def _parsing_error_message(checkov_output: dict[str, Any]) -> str | None:
    """Describe Checkov parsing errors, including filenames when available."""
    summary = checkov_output.get("summary")
    if not isinstance(summary, dict):
        raise CheckovRuntimeError(
            "Checkov output did not include a summary; the scan cannot be "
            "trusted as complete"
        )

    parsing_errors = summary.get("parsing_errors")
    if isinstance(parsing_errors, bool) or not isinstance(parsing_errors, int):
        raise CheckovRuntimeError(
            "Checkov output contained an invalid summary.parsing_errors value; "
            "the scan cannot be trusted as complete"
        )

    results = checkov_output.get("results")
    result_errors = results.get("parsing_errors") if isinstance(results, dict) else None
    if result_errors is not None and not isinstance(result_errors, list):
        raise CheckovRuntimeError(
            "Checkov output contained an invalid results.parsing_errors value; "
            "the scan cannot be trusted as complete"
        )

    # The summary is authoritative for the count. A non-empty details list is
    # also a failure if an output variant reports an inconsistent count.
    if parsing_errors <= 0 and not result_errors:
        return None

    details = [str(path) for path in (result_errors or []) if path]
    suffix = f": {', '.join(details)}" if details else ""
    return f"Checkov reported {max(parsing_errors, len(details))} parsing error(s){suffix}"


def _validate_scan_output(checkov_output: Any, iac_type: str) -> dict[str, Any]:
    """Validate the trusted runner's output before it reaches report mapping."""
    if not isinstance(checkov_output, dict):
        raise CheckovRuntimeError(
            "Checkov returned a JSON value that is not an object; "
            "the scan cannot be trusted as complete"
        )

    if "check_type" in checkov_output and checkov_output["check_type"] != iac_type:
        raise CheckovRuntimeError(
            f"Checkov returned check_type {checkov_output['check_type']!r}, "
            f"but the requested IaC type was {iac_type!r}"
        )

    # Checkov emits only summary fields when a source directory contains no
    # files it can scan. Treat that as a scanner failure rather than a clean
    # result, because the wrapper cannot claim that the requested source was
    # inspected.
    if "results" not in checkov_output:
        raise CheckovRuntimeError(
            f"Checkov returned no {iac_type} scan results; the target may be "
            "empty or contain no supported files"
        )

    error = _parsing_error_message(checkov_output)
    if error:
        raise CheckovRuntimeError(error)
    try:
        _validate_checkov_output(checkov_output)
    except ValueError as exc:
        raise CheckovRuntimeError(
            f"Checkov returned a malformed failed finding: {exc}"
        ) from exc
    return checkov_output


def _reject_unsupported_source_files(target: Path, iac_type: str) -> None:
    """Reject source formats that Checkov silently ignores for this framework."""
    if iac_type != "terraform":
        return
    json_sources = sorted(target.rglob("*.tf.json"))
    if json_sources:
        names = ", ".join(str(path) for path in json_sources[:5])
        if len(json_sources) > 5:
            names += f", ... and {len(json_sources) - 5} more"
        raise ValueError(
            "Terraform JSON source files (*.tf.json) are not supported by "
            f"Checkov's {iac_type} source framework: {names}. Convert the "
            "configuration to .tf HCL or scan a Terraform plan JSON with "
            "--iac-type terraform_plan."
        )


def _is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is inside *root*, including the root itself."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_scan_root_symlinks(scan_root: Path) -> None:
    """Reject links that escape a directory scan's resolved root.

    In-root symlinks are allowed. Their resolved directories are inspected as
    well, while real directories are visited only once so an in-root symlink
    cycle cannot make validation loop forever. Broken or unresolvable links
    fail closed as invalid scan input.
    """
    root = scan_root.resolve(strict=True)
    pending = [root]
    visited: set[Path] = set()

    while pending:
        current = pending.pop().resolve(strict=True)
        if current in visited:
            continue
        visited.add(current)

        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            raise ValueError(
                f"Cannot inspect scan root '{current}' while validating symlinks: {exc}"
            ) from exc

        for entry in entries:
            candidate = Path(entry.path)
            if entry.is_symlink():
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        f"Symlink '{candidate}' is broken or cannot be resolved"
                    ) from exc
                if not _is_within(resolved, root):
                    raise ValueError(
                        f"Symlink '{candidate}' resolves outside scan root '{root}' "
                        f"to '{resolved}'"
                    )
                if resolved.is_dir():
                    pending.append(resolved)
            elif entry.is_dir(follow_symlinks=False):
                pending.append(candidate)


def run_checkov(target: Path, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Run Checkov against an IaC directory **or** a plan file, and return parsed JSON.

    ``terraform_plan`` scans a single ``terraform show -json`` output file via
    Checkov's ``-f`` flag; every other IaC type scans a directory via ``-d``.

    Args:
        target: Path to a directory containing IaC files, or — for
            ``iac_type="terraform_plan"`` — the path of the plan JSON file
        iac_type: Which IaC language to scan — one of
            :data:`SUPPORTED_IAC_TYPES`, passed through to Checkov's
            ``--framework`` flag. Unrelated to the CLI's ``--framework``
            compliance-regime filter.

    Returns:
        Parsed JSON output from Checkov

    Raises:
        ValueError: If ``iac_type`` is not a supported IaC type, or the
            target doesn't match the invocation shape (directory vs. file)
        FileNotFoundError: If ``target`` does not exist
        CheckovRuntimeError: If Checkov exits with an error or returns invalid JSON
    """
    if iac_type not in SUPPORTED_IAC_TYPES:
        raise ValueError(
            f"Unsupported iac_type '{iac_type}' — expected one of "
            f"{', '.join(SUPPORTED_IAC_TYPES)}"
        )
    target = Path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    # tf-eu-guard's custom EU-compliance checks (EUGUARD_*) live alongside this
    # module; load them so a normal scan produces stock (CKV_AWS_*) *and* custom
    # findings. Each check subdir carries an __init__.py, which Checkov's
    # external-check loader requires.
    checks_dir = Path(__file__).parent / "checks"

    # terraform_plan files are single JSON documents, not directories —
    # Checkov needs -f <plan.json> for those, -d <dir> for everything else.
    if iac_type == "terraform_plan":
        if not target.is_file():
            raise ValueError(
                f"terraform_plan requires a plan file (terraform show -json "
                f"output), but '{target}' is not a file"
            )
        target_flag = ["-f", str(target)]
    else:
        if not target.is_dir():
            raise ValueError(
                f"iac_type '{iac_type}' scans a directory, but '{target}' is not a directory"
            )
        _validate_scan_root_symlinks(target)
        _reject_unsupported_source_files(target, iac_type)
        target_flag = ["-d", str(target)]

    # Invoke the installed Checkov module through this process's interpreter.
    # ``-I`` removes cwd/PYTHONPATH/user-site module shadowing, and the trusted
    # cwd keeps the scanned checkout out of the child process's import context.
    # The small bootstrap also disables Checkov's automatic config discovery;
    # the wrapper's required checks must not be suppressed by a checkout's
    # .checkov.yml/.checkov.yaml or by Checkov filter environment variables.
    cmd = [
        sys.executable, "-I", "-c", _CHECKOV_BOOTSTRAP,
        *target_flag,
        "--external-checks-dir", str(checks_dir),
        "--output", "json",
        "--framework", iac_type,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,  # Don't raise on non-zero exit (Checkov returns 1 when findings exist)
        cwd=_trusted_checkov_workdir(),
        env=_checkov_environment(),
    )

    if result.returncode not in (0, 1):
        # Exit code 2+ indicates actual error, not just findings
        raise CheckovRuntimeError(
            f"Checkov exited with status {result.returncode}. "
            f"Last stderr lines:\n{_stderr_tail(result.stderr)}"
        )

    try:
        checkov_output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckovRuntimeError(
            f"Checkov returned invalid JSON: {exc}. "
            f"Last stderr lines:\n{_stderr_tail(result.stderr)}"
        ) from exc

    return _validate_scan_output(checkov_output, iac_type)


def load_checkov_json(json_source: Path, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Load a pre-generated Checkov JSON result instead of running Checkov.

    Accepts a file path, or ``"-"`` to read from stdin — e.g. piped from
    ``checkov -d <dir> --output json --framework <iac_type> --quiet``.

    Args:
        json_source: Path to a Checkov JSON file, or ``Path("-")`` for stdin
        iac_type: Which IaC language the JSON was produced for — used to pick
            the right element when Checkov returns a multi-framework array

    Returns:
        A single Checkov result object (``{"results": {...}, ...}``) ready for
        ``extract_failed_checks``. Multi-check-type Checkov output (a JSON array)
        is normalized down to the ``iac_type`` element.

    Raises:
        FileNotFoundError: If the file does not exist
        json.JSONDecodeError: If the content is not valid JSON
        ValueError: If the JSON is not a usable Checkov result shape
    """
    if str(json_source) == "-":
        text = sys.stdin.read()
    else:
        path = Path(json_source)
        if path.is_dir():
            raise CheckovInputError(
                f"Checkov JSON input must be a file, not a directory: {path}"
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (IsADirectoryError, NotADirectoryError, PermissionError) as exc:
            raise CheckovInputError(
                f"Cannot read Checkov JSON input '{path}': {exc.strerror or exc}"
            ) from exc

    return _normalize_checkov_output(json.loads(text), iac_type)


def _normalize_checkov_output(data: Any, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Normalize Checkov JSON into the single-object form ``extract_failed_checks`` expects.

    Checkov emits a single object for one check type, but a JSON *array* of objects
    when several run (e.g. terraform + secrets). A declared ``check_type`` must
    match the requested IaC type. A single legacy object that omits ``check_type``
    remains accepted for compatibility with older Checkov captures; arrays must
    contain an explicitly matching element.
    """
    if isinstance(data, dict):
        if "check_type" in data and data["check_type"] != iac_type:
            raise ValueError(
                f"Checkov JSON declares check_type {data['check_type']!r}, "
                f"but --iac-type is {iac_type!r}"
            )
        return data

    if isinstance(data, list):
        for element in data:
            if isinstance(element, dict) and element.get("check_type") == iac_type:
                return element
        raise ValueError(
            f"Checkov JSON array contained no result object with "
            f"check_type {iac_type!r}; refusing to use a result for another "
            "IaC framework"
        )

    raise ValueError(
        f"Unexpected Checkov JSON shape: expected an object or array, "
        f"got {type(data).__name__}."
    )


def _validate_checkov_output(checkov_output: dict[str, Any]) -> None:
    """
    Assert the input is shaped like Checkov output (has ``results.failed_checks``).

    Silent empty results on non-Checkov input (e.g. raw ``terraform show -json``
    plan output piped into ``--checkov-json``) previously masked shape
    mismatches as clean "0 findings" scans — this guard makes those fail loudly.
    """
    if not isinstance(checkov_output, dict) or "results" not in checkov_output:
        got = _describe_json_shape(checkov_output)
        raise ValueError(
            "Input does not look like Checkov output: expected an object with "
            f"a 'results' key, got {got}. If this is a raw "
            "'terraform show -json' plan file, scan it directly: "
            "tf-eu-guard scan <plan.json> --iac-type terraform_plan"
        )
    results = checkov_output["results"]
    if not isinstance(results, dict) or "failed_checks" not in results:
        got = _describe_json_shape(checkov_output)
        raise ValueError(
            "Input does not look like Checkov output: expected "
            f"'results.failed_checks', got {got}. If this is a raw "
            "'terraform show -json' plan file, scan it directly: "
            "tf-eu-guard scan <plan.json> --iac-type terraform_plan"
        )
    failed_checks = results["failed_checks"]
    if not isinstance(failed_checks, list):
        raise ValueError(
            "Input does not look like Checkov output: "
            "'results.failed_checks' must be a list of objects"
        )
    for index, check in enumerate(failed_checks):
        if not isinstance(check, dict):
            raise ValueError(
                "Input does not look like Checkov output: "
                f"'results.failed_checks[{index}]' must be an object"
            )
        _validate_failed_check(check, index)


def _validate_failed_check(check: dict[str, Any], index: int) -> None:
    """Validate the Checkov fields required by every downstream reporter."""
    prefix = f"'results.failed_checks[{index}]'"
    required_fields = (
        "check_id",
        "check_name",
        "resource",
        "file_path",
        "file_line_range",
    )
    missing = [field for field in required_fields if field not in check]
    if missing:
        raise ValueError(f"{prefix} missing required field(s): {', '.join(missing)}")

    check_id = check["check_id"]
    if not isinstance(check_id, str) or not check_id.strip():
        raise ValueError(f"{prefix}.check_id must be a non-empty string")

    check_name = check["check_name"]
    if not isinstance(check_name, str) or not check_name.strip():
        raise ValueError(f"{prefix}.check_name must be a non-empty string")

    for field in ("resource", "file_path"):
        if not isinstance(check[field], str):
            raise ValueError(f"{prefix}.{field} must be a string")

    line_range = check["file_line_range"]
    if (
        not isinstance(line_range, list)
        or len(line_range) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) for value in line_range)
        or line_range[0] < 0
        or line_range[1] < line_range[0]
    ):
        raise ValueError(
            f"{prefix}.file_line_range must contain two ordered non-negative integers"
        )


def _describe_json_shape(data: Any) -> str:
    """One-line human description of a parsed-JSON value's shape for errors."""
    if isinstance(data, dict):
        keys = ", ".join(sorted(data.keys())[:5]) or "no keys"
        return f"an object with keys: {keys}"
    if isinstance(data, list):
        return f"an array with {len(data)} element(s)"
    return f"a {type(data).__name__}"


def extract_failed_checks(checkov_output: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract failed check details from Checkov JSON output.

    Args:
        checkov_output: Parsed Checkov JSON result

    Returns:
        List of failed check dictionaries with fields:
        - check_id: e.g. "CKV_AWS_18"
        - check_name: Human-readable check name
        - resource: Resource address (e.g. "aws_s3_bucket.data")
        - file_path: Relative path to .tf file
        - file_line_range: [start_line, end_line]
        - guideline: Checkov's remediation link

    Raises:
        ValueError: If the input is not Checkov-shaped (no
            ``results.failed_checks``) — e.g. a raw Terraform plan JSON
    """
    _validate_checkov_output(checkov_output)
    failed = []

    # Checkov JSON structure: results -> failed_checks (list)
    for check in checkov_output.get("results", {}).get("failed_checks", []):
        failed.append({
            "check_id": check.get("check_id"),
            "check_name": check.get("check_name"),
            "resource": check.get("resource"),
            "file_path": check.get("file_path"),
            "file_line_range": check.get("file_line_range", [0, 0]),
            "guideline": check.get("guideline"),
        })

    return failed
