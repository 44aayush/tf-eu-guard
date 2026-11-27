"""Validation and normalization for Checkov JSON output."""

import codecs
import json
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from importlib import metadata
from pathlib import Path
from typing import Any

from tf_eu_guard.checkov.types import CheckovInputError, CheckovRuntimeError

#: Set by the CLI for ``--allow-partial``: parsing errors then warn instead of fail.
_ALLOW_PARTIAL: ContextVar[bool] = ContextVar("tf_eu_guard_allow_partial", default=False)

#: Directory of the package's custom ``EUGUARD_*`` checks.
CUSTOM_CHECKS_DIR = Path(__file__).resolve().parent.parent / "checks"
CUSTOM_CHECK_PREFIX = "EUGUARD_"


@contextmanager
def allow_partial_results(allow: bool) -> Iterator[None]:
    """Downgrade Checkov parsing errors to a stderr warning within the block."""
    token = _ALLOW_PARTIAL.set(allow)
    try:
        yield
    finally:
        _ALLOW_PARTIAL.reset(token)


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


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


def validate_scan_output(
    checkov_output: Any, iac_type: str, extra_check_types: Sequence[str] = ()
) -> dict[str, Any]:
    """Validate the trusted runner's output before it reaches report mapping.

    With *extra_check_types* the runner returns an array; the extra elements
    are merged first (see :func:`normalize_checkov_output`), so their parsing
    errors count toward the fail-closed rule.
    """
    if extra_check_types and isinstance(checkov_output, list):
        try:
            checkov_output = normalize_checkov_output(checkov_output, iac_type, extra_check_types)
        except ValueError as exc:
            raise CheckovRuntimeError(str(exc)) from exc
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
        if not _ALLOW_PARTIAL.get():
            raise CheckovRuntimeError(error)
        _warn(f"{error}; continuing because --allow-partial was given. The result is incomplete.")
    try:
        validate_checkov_output(checkov_output)
    except ValueError as exc:
        raise CheckovRuntimeError(f"Checkov returned a malformed finding: {exc}") from exc
    return checkov_output


def decode_json_bytes(raw: bytes, source: str = "input") -> str:
    """Decode JSON bytes, honouring a UTF-8-SIG or UTF-16 byte-order mark.

    Windows PowerShell 5 writes redirected output as UTF-16 LE with a BOM;
    many editors add a UTF-8 BOM. Without a BOM the bytes are UTF-8.
    """
    if raw.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"  # consumes the BOM and picks the byte order
    else:
        encoding = "utf-8"
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise CheckovInputError(
            f"Cannot decode Checkov JSON {source} as {encoding}: {exc.reason}. "
            "Re-save it as UTF-8 (in PowerShell 5 use '| Out-File -Encoding utf8')."
        ) from exc


def load_checkov_json(
    json_source: Path,
    iac_type: str = "terraform",
    extra_check_types: Sequence[str] = (),
    require_complete: bool = False,
) -> dict[str, Any]:
    """Load and normalize a pre-generated Checkov JSON result.

    With *require_complete* (a gate is set) an input without any ``EUGUARD_*`` check or
    with ``summary.resource_count`` 0 raises instead of warning, unless
    ``--allow-partial`` is in effect: a forged or empty file would otherwise pass every gate.
    """
    if str(json_source) == "-":
        buffer = getattr(sys.stdin, "buffer", None)
        text = decode_json_bytes(buffer.read(), "from stdin") if buffer else sys.stdin.read()
    else:
        path = Path(json_source)
        if path.is_dir():
            raise CheckovInputError(f"Checkov JSON input must be a file, not a directory: {path}")
        try:
            text = decode_json_bytes(path.read_bytes(), f"file '{path}'")
        except (IsADirectoryError, NotADirectoryError, PermissionError) as exc:
            raise CheckovInputError(
                f"Cannot read Checkov JSON input '{path}': {exc.strerror or exc}"
            ) from exc

    data = json.loads(text)
    _check_parsing_errors(data)
    output = normalize_checkov_output(data, iac_type, extra_check_types)
    _warn_installed_version_mismatch(output)
    _check_input_completeness(output, require_complete)
    return output


def _lenient_parsing_error_message(element: dict[str, Any]) -> str | None:
    """Like :func:`parsing_error_message`, but tolerant of absent or odd summaries."""
    summary = element.get("summary")
    if not isinstance(summary, dict) or "parsing_errors" not in summary:
        results = element.get("results")
        if not (isinstance(results, dict) and results.get("parsing_errors")):
            return None
    return parsing_error_message(element)


def _check_parsing_errors(data: Any) -> None:
    """Fail (or warn with ``--allow-partial``) when the input reports parsing errors.

    Mirrors the source-scan rule. For a list of per-framework results every
    element counts, since an error in any framework means incomplete coverage.
    """
    elements = data if isinstance(data, list) else [data]
    messages = [
        message
        for element in elements
        if isinstance(element, dict)
        for message in [_lenient_parsing_error_message(element)]
        if message
    ]
    if not messages:
        return
    error = "; ".join(messages)
    if not _ALLOW_PARTIAL.get():
        raise CheckovRuntimeError(
            f"{error} (in the --checkov-json input); the scan cannot be trusted as complete. "
            "Fix the parsing errors and regenerate the file, or pass --allow-partial."
        )
    _warn(f"{error}; continuing because --allow-partial was given. The result is incomplete.")


def installed_checkov_version() -> str | None:
    """Return the installed Checkov version, or ``None`` when not installed."""
    try:
        return metadata.version("checkov")
    except metadata.PackageNotFoundError:
        return None


def checkov_version_of(output: dict[str, Any]) -> str | None:
    """Return ``summary.checkov_version`` when present."""
    summary = output.get("summary")
    version = summary.get("checkov_version") if isinstance(summary, dict) else None
    return version if isinstance(version, str) and version else None


def _warn_installed_version_mismatch(output: dict[str, Any]) -> None:
    declared = checkov_version_of(output)
    installed = installed_checkov_version()
    if declared and installed and declared != installed:
        _warn(
            f"the Checkov JSON was produced by Checkov {declared}, but Checkov {installed} "
            "is installed. Check IDs and result fields can differ between versions."
        )


def _has_custom_check(results: dict[str, Any]) -> bool:
    for section in ("passed_checks", "failed_checks", "skipped_checks"):
        for check in results.get(section) or []:
            check_id = check.get("check_id") if isinstance(check, dict) else None
            if isinstance(check_id, str) and check_id.startswith(CUSTOM_CHECK_PREFIX):
                return True
    return False


def _check_input_completeness(output: dict[str, Any], require_complete: bool) -> None:
    """Warn about a file that may not be a full scan; with *require_complete* fail unless it reports a positive count.

    Absence of ``EUGUARD_*`` results only warns: the residency checks need a region or
    location in the source (AWS, Azure or GCP) and Checkov omits UNKNOWN results, so genuine
    output for region-less code has none.
    """
    strict = require_complete and not _ALLOW_PARTIAL.get()
    results = output.get("results")
    if isinstance(results, dict) and not _has_custom_check(results):
        _warn(
            "no EUGUARD_* result appears in the Checkov JSON. If it was generated without "
            f"--external-checks-dir {CUSTOM_CHECKS_DIR}, the data-residency and secret-in-code "
            "checks did not run and a clean result does not cover them. (The residency checks "
            "need a region or location in the source, so region-less input legitimately has "
            "none.)"
        )
    summary = output.get("summary")
    count = summary.get("resource_count") if isinstance(summary, dict) else None
    is_int = isinstance(count, int) and not isinstance(count, bool)
    if is_int and count == 0:
        if strict:
            raise CheckovRuntimeError(
                "the Checkov JSON reports 0 resources scanned; a gated scan cannot trust it. "
                "Pass --allow-partial to accept it"
            )
        _warn("the Checkov JSON reports 0 resources scanned")
    elif strict and not (is_int and count is not None and count >= 1):
        raise CheckovRuntimeError(
            "the Checkov JSON does not report a positive resource_count; a gated scan cannot "
            "trust it. Pass --allow-partial to accept it"
        )


#: The only fields copied from an extra (secrets) result. Checkov's secrets
#: records also carry ``code_block``, ``details`` and a hash in ``resource``,
#: all derived from the secret value, so anything not listed here is dropped.
_EXTRA_CHECK_FIELDS = ("check_id", "check_name", "file_path", "file_line_range", "guideline")


def _sanitize_extra_check(check: Any) -> Any:
    """Return *check* reduced to non-secret fields (non-dicts pass through to validation)."""
    if not isinstance(check, dict):
        return check
    clean = {k: check[k] for k in _EXTRA_CHECK_FIELDS if k in check}
    if "resource" in check:
        # Checkov's secrets ``resource`` is a hash of the secret; use the location.
        line_range = check.get("file_line_range")
        line = line_range[0] if isinstance(line_range, list) and line_range else 0
        clean["resource"] = f"secret@{check.get('file_path')}:{line}"
    result = check.get("check_result")
    if isinstance(result, dict) and "suppress_comment" in result:
        clean["check_result"] = {"suppress_comment": result["suppress_comment"]}
    return clean


def _merge_extra_element(merged: dict[str, Any], extra: dict[str, Any]) -> None:
    results = extra.get("results")
    if isinstance(results, dict):
        for section in ("failed_checks", "passed_checks", "skipped_checks"):
            items = results.get(section)
            if isinstance(items, list):
                merged["results"].setdefault(section, [])
                merged["results"][section] = [
                    *merged["results"][section],
                    *map(_sanitize_extra_check, items),
                ]
        errors = results.get("parsing_errors")
        if isinstance(errors, list) and errors:
            merged["results"]["parsing_errors"] = [
                *(merged["results"].get("parsing_errors") or []),
                *errors,
            ]
    extra_summary = extra.get("summary")
    if not isinstance(extra_summary, dict) or not isinstance(merged.get("summary"), dict):
        return

    def count(summary: dict[str, Any], key: str) -> int:
        value = summary.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    summary = merged["summary"]
    # Keep the totals (provenance) in step with the merged findings.
    for key in ("parsing_errors", "passed", "failed", "skipped", "resource_count"):
        if key == "parsing_errors" and not count(extra_summary, key):
            continue
        summary[key] = count(summary, key) + count(extra_summary, key)


def normalize_checkov_output(
    data: Any, iac_type: str = "terraform", extra_check_types: Sequence[str] = ()
) -> dict[str, Any]:
    """Normalize Checkov JSON into the single-object form used by extraction.

    Elements whose ``check_type`` is in *extra_check_types* (for example
    ``secrets``) are merged into the *iac_type* element; an absent extra element
    means zero results, because Checkov omits frameworks with nothing to report.
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
                if not extra_check_types:
                    return element
                merged = {
                    **element,
                    "results": dict(element["results"])
                    if isinstance(element.get("results"), dict)
                    else element.get("results"),
                    "summary": dict(element["summary"])
                    if isinstance(element.get("summary"), dict)
                    else element.get("summary"),
                }
                if isinstance(merged["results"], dict):
                    for extra in data:
                        if isinstance(extra, dict) and extra.get("check_type") in extra_check_types:
                            _merge_extra_element(merged, extra)
                return merged
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

    # ``skipped_checks`` holds findings suppressed by inline comments. Older
    # outputs and fixtures omit it, so a missing key is accepted; a present
    # one is validated as strictly as ``failed_checks``.
    # ``passed_checks`` (the requirement evidence matrix) is validated the same way.
    for section in ("skipped_checks", "passed_checks"):
        checks = results.get(section)
        if checks is None:
            continue
        if not isinstance(checks, list):
            raise ValueError(
                f"Input does not look like Checkov output: 'results.{section}' "
                "must be a list of objects"
            )
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                raise ValueError(
                    "Input does not look like Checkov output: "
                    f"'results.{section}[{index}]' must be an object"
                )
            validate_failed_check(check, index, section=section)


def validate_failed_check(
    check: dict[str, Any], index: int, section: str = "failed_checks"
) -> None:
    """Validate the Checkov fields required by every downstream reporter."""
    prefix = f"'results.{section}[{index}]'"
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


#: Checkov's placeholder when a skip comment carries no reason.
_NO_COMMENT_PLACEHOLDER = "No comment provided"


def suppression_reason(check: dict[str, Any]) -> str | None:
    """Return the stated reason of a skipped check, or ``None`` when absent."""
    check_result = check.get("check_result")
    if not isinstance(check_result, dict):
        return None
    comment = check_result.get("suppress_comment")
    if not isinstance(comment, str):
        return None
    comment = comment.strip()
    if not comment or comment == _NO_COMMENT_PLACEHOLDER:
        return None
    return comment


def extract_passed_checks(checkov_output: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract passed checks; entries have the shape of :func:`extract_failed_checks`."""
    validate_checkov_output(checkov_output)
    return [
        {
            "check_id": check.get("check_id"),
            "check_name": check.get("check_name"),
            "resource": check.get("resource"),
            "file_path": check.get("file_path"),
            "file_line_range": check.get("file_line_range", [0, 0]),
            "guideline": check.get("guideline"),
        }
        for check in checkov_output.get("results", {}).get("passed_checks") or []
    ]


def extract_skipped_checks(checkov_output: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract checks suppressed by inline ``checkov:skip`` comments.

    Entries have the same shape as :func:`extract_failed_checks` plus
    ``suppressed: True`` and ``suppression_reason`` (``None`` if none given).
    """
    validate_checkov_output(checkov_output)
    skipped = []
    for check in checkov_output.get("results", {}).get("skipped_checks") or []:
        skipped.append(
            {
                "check_id": check.get("check_id"),
                "check_name": check.get("check_name"),
                "resource": check.get("resource"),
                "file_path": check.get("file_path"),
                "file_line_range": check.get("file_line_range", [0, 0]),
                "guideline": check.get("guideline"),
                "suppressed": True,
                "suppression_reason": suppression_reason(check),
            }
        )
    return skipped
