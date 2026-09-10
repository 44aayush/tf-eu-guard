"""Checkov runner module — invokes Checkov programmatically."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from tf_eu_guard.constants import SUPPORTED_IAC_TYPES


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
        subprocess.CalledProcessError: If Checkov execution fails
        json.JSONDecodeError: If Checkov output is not valid JSON
    """
    if iac_type not in SUPPORTED_IAC_TYPES:
        raise ValueError(
            f"Unsupported iac_type '{iac_type}' — expected one of "
            f"{', '.join(SUPPORTED_IAC_TYPES)}"
        )
    if not Path(target).exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    # tf-eu-guard's custom EU-compliance checks (EUGUARD_*) live alongside this
    # module; load them so a normal scan produces stock (CKV_AWS_*) *and* custom
    # findings. Each check subdir carries an __init__.py, which Checkov's
    # external-check loader requires.
    checks_dir = Path(__file__).parent / "checks"

    # terraform_plan files are single JSON documents, not directories —
    # Checkov needs -f <plan.json> for those, -d <dir> for everything else.
    if iac_type == "terraform_plan":
        if not Path(target).is_file():
            raise ValueError(
                f"terraform_plan requires a plan file (terraform show -json "
                f"output), but '{target}' is not a file"
            )
        target_flag = ["-f", str(target)]
    else:
        if not Path(target).is_dir():
            raise ValueError(
                f"iac_type '{iac_type}' scans a directory, but '{target}' is not a directory"
            )
        target_flag = ["-d", str(target)]

    # Invoke Checkov through this process's interpreter so PATH ordering cannot
    # select a different global Checkov installation from tf-eu-guard's own
    # Python environment. The module is "checkov.main" (not "checkov") because
    # Checkov ships no package-level __main__.py — `python -m checkov` fails.
    cmd = [
        sys.executable, "-m", "checkov.main",
        *target_flag,
        "--external-checks-dir", str(checks_dir),
        "--output", "json",
        "--framework", iac_type,
        "--quiet",  # Suppress progress bars
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,  # Don't raise on non-zero exit (Checkov returns 1 when findings exist)
    )

    if result.returncode not in (0, 1):
        # Exit code 2+ indicates actual error, not just findings
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            output=result.stdout,
            stderr=result.stderr,
        )

    return json.loads(result.stdout)


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
        text = Path(json_source).read_text()

    return _normalize_checkov_output(json.loads(text), iac_type)


def _normalize_checkov_output(data: Any, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Normalize Checkov JSON into the single-object form ``extract_failed_checks`` expects.

    Checkov emits a single object for one check type, but a JSON *array* of objects
    when several run (e.g. terraform + secrets). We select the ``iac_type`` element,
    falling back to the first object present.
    """
    if isinstance(data, dict):
        return data

    if isinstance(data, list):
        for element in data:
            if isinstance(element, dict) and element.get("check_type") == iac_type:
                return element
        for element in data:
            if isinstance(element, dict):
                return element
        raise ValueError(
            "Checkov JSON array contained no usable result objects "
            "(expected at least one object with a 'results' key)."
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
