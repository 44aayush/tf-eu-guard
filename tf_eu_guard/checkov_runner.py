"""Checkov runner module — invokes Checkov programmatically."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

#: IaC types tf-eu-guard can scan, mapped to Checkov's ``--framework`` values.
SUPPORTED_IAC_TYPES = ("terraform", "terraform_plan", "kubernetes")


def run_checkov(target_dir: Path, iac_type: str = "terraform") -> dict[str, Any]:
    """
    Run Checkov against an IaC directory and return parsed JSON results.

    Args:
        target_dir: Path to directory containing IaC files
        iac_type: Which IaC language to scan — one of
            :data:`SUPPORTED_IAC_TYPES`, passed through to Checkov's
            ``--framework`` flag. Unrelated to the CLI's ``--framework``
            compliance-regime filter.

    Returns:
        Parsed JSON output from Checkov

    Raises:
        ValueError: If ``iac_type`` is not a supported IaC type
        subprocess.CalledProcessError: If Checkov execution fails
        json.JSONDecodeError: If Checkov output is not valid JSON
    """
    if iac_type not in SUPPORTED_IAC_TYPES:
        raise ValueError(
            f"Unsupported iac_type '{iac_type}' — expected one of "
            f"{', '.join(SUPPORTED_IAC_TYPES)}"
        )

    # tf-eu-guard's custom EU-compliance checks (EUGUARD_*) live alongside this
    # module; load them so a normal scan produces stock (CKV_AWS_*) *and* custom
    # findings. Each check subdir carries an __init__.py, which Checkov's
    # external-check loader requires.
    checks_dir = Path(__file__).parent / "checks"

    cmd = [
        "checkov",
        "-d", str(target_dir),
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
    """
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
