"""Validation and normalization for Checkov JSON output."""

import json
import sys
from pathlib import Path
from typing import Any

from tf_eu_guard.checkov.types import CheckovInputError, CheckovRuntimeError


def parsing_error_message(checkov_output: dict[str, Any]) -> str | None:
    """Describe Checkov parsing errors, including filenames when available."""
    summary = checkov_output.get("summary")
    if not isinstance(summary, dict):
        raise CheckovRuntimeError(
            "Checkov output did not include a summary; the scan cannot be trusted as complete"
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


def validate_scan_output(checkov_output: Any, iac_type: str) -> dict[str, Any]:
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

    error = parsing_error_message(checkov_output)
    if error:
        raise CheckovRuntimeError(error)
    try:
        validate_checkov_output(checkov_output)
    except ValueError as exc:
        raise CheckovRuntimeError(f"Checkov returned a malformed failed finding: {exc}") from exc
    return checkov_output


def load_checkov_json(json_source: Path, iac_type: str = "terraform") -> dict[str, Any]:
    """Load and normalize a pre-generated Checkov JSON result."""
    if str(json_source) == "-":
        text = sys.stdin.read()
    else:
        path = Path(json_source)
        if path.is_dir():
            raise CheckovInputError(f"Checkov JSON input must be a file, not a directory: {path}")
        try:
            text = path.read_text(encoding="utf-8")
        except (IsADirectoryError, NotADirectoryError, PermissionError) as exc:
            raise CheckovInputError(
                f"Cannot read Checkov JSON input '{path}': {exc.strerror or exc}"
            ) from exc

    return normalize_checkov_output(json.loads(text), iac_type)


def normalize_checkov_output(data: Any, iac_type: str = "terraform") -> dict[str, Any]:
    """Normalize Checkov JSON into the single-object form used by extraction."""
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
        f"Unexpected Checkov JSON shape: expected an object or array, got {type(data).__name__}."
    )


def validate_checkov_output(checkov_output: dict[str, Any]) -> None:
    """Validate the fields required by downstream reporters."""
    if not isinstance(checkov_output, dict) or "results" not in checkov_output:
        got = describe_json_shape(checkov_output)
        raise ValueError(
            "Input does not look like Checkov output: expected an object with "
            f"a 'results' key, got {got}. If this is a raw "
            "'terraform show -json' plan file, scan it directly: "
            "tf-eu-guard scan <plan.json> --iac-type terraform_plan"
        )
    results = checkov_output["results"]
    if not isinstance(results, dict) or "failed_checks" not in results:
        got = describe_json_shape(checkov_output)
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
        validate_failed_check(check, index)


def validate_failed_check(check: dict[str, Any], index: int) -> None:
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
        raise ValueError(f"{prefix}.file_line_range must contain two ordered non-negative integers")


def describe_json_shape(data: Any) -> str:
    """Return a one-line human description of a parsed JSON value's shape."""
    if isinstance(data, dict):
        keys = ", ".join(sorted(data.keys())[:5]) or "no keys"
        return f"an object with keys: {keys}"
    if isinstance(data, list):
        return f"an array with {len(data)} element(s)"
    return f"a {type(data).__name__}"


def extract_failed_checks(checkov_output: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the failed check details needed by the reporting pipeline."""
    validate_checkov_output(checkov_output)
    failed = []

    # Checkov JSON structure: results -> failed_checks (list)
    for check in checkov_output.get("results", {}).get("failed_checks", []):
        failed.append(
            {
                "check_id": check.get("check_id"),
                "check_name": check.get("check_name"),
                "resource": check.get("resource"),
                "file_path": check.get("file_path"),
                "file_line_range": check.get("file_line_range", [0, 0]),
                "guideline": check.get("guideline"),
            }
        )

    return failed
