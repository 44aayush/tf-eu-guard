"""SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.

Each finding becomes a SARIF ``result`` whose ``ruleId`` is the Checkov
check ID; the registry's regulatory context (NIS2/GDPR articles, severity,
remediation) rides along in ``properties`` on both the ``tool.driver.rules``
entry and the per-result ``properties``, so Code Scanning surfaces the
article metadata without extra clicks. Unmapped Checkov findings are
included as low-visibility ``note``-level results tagged
``properties.mapped = false`` rather than silently dropped — the same
surface-them-anywhere policy the HTML and JSON reports follow.

The output is validated against the official OASIS SARIF 2.1.0 JSON Schema
in ``tests/test_sarif_report.py`` (schema vendored under
``tests/schemas/``), not just eyeballed.
"""

import ntpath
import posixpath
import re
from pathlib import Path, PureWindowsPath
from typing import Any, cast
from urllib.parse import quote

from tf_eu_guard.models import EnrichedFinding, Severity
from tf_eu_guard.reporting.html_common import safe_guideline
from tf_eu_guard.reporting.sorting import (
    finding_sort_key,
    sort_findings,
    sort_unmapped_findings,
    sorted_articles,
    unmapped_sort_key,
)

#: The OASIS SARIF 2.1.0 schema this output targets (what Code Scanning
#: ingests). Also the ``$schema`` value written into the document itself.
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

#: Severities that map to each SARIF level. Code Scanning renders ``error``
#: and ``warning`` prominently; ``note`` is informationally visible.
_ERROR = (Severity.CRITICAL, Severity.HIGH)
_NOTE = (Severity.LOW, Severity.INFO)


def sarif_level(severity: Severity) -> str:
    """Map a registry severity to a SARIF level (error/warning/note)."""
    if severity in _ERROR:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _articles_property(finding: EnrichedFinding) -> list[str]:
    """Article references as ``"NIS2 Art. 21(2)(i)"`` style labels."""
    return [f"{a.framework.value} {a.article}" for a in sorted_articles(finding)]


def _required_check_id(value: object) -> str:
    """Return a usable SARIF rule ID instead of ever serializing ``null``."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("SARIF rule IDs must be non-empty strings")
    return value


_WINDOWS_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:/|//)")


def _path_text(value: object) -> str:
    """Return a filesystem value as slash-normalized text."""
    return str(value or "").replace("\\", "/")


def _is_windows_absolute(path: str) -> bool:
    """Return whether *path* has a Windows drive or UNC absolute prefix."""
    return bool(_WINDOWS_ABSOLUTE.match(path))


def _is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is inside *root*, including the root itself."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _posix_root(value: object, base: Path | None = None) -> Path:
    """Resolve a local path without requiring the artifact to exist."""
    path = Path(_path_text(value)).expanduser()
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    # ``resolve(strict=False)`` also removes lexical ``..`` components and
    # follows existing symlinks, so the repository-boundary check below is
    # effective for both traversal and symlink escapes.
    return path.resolve(strict=False)


def _windows_root(value: object, base: PureWindowsPath | None = None) -> PureWindowsPath:
    """Resolve a Windows-style root lexically, independent of host OS."""
    path = PureWindowsPath(ntpath.normpath(_path_text(value)))
    if not path.is_absolute() and base is not None:
        path = base / path
    return PureWindowsPath(ntpath.normpath(path.as_posix()))


def _windows_artifact_path(
    path: str,
    scan_root: object | None,
    repository_root: object | None,
) -> str | None:
    """Return a Windows artifact path relative to the repository boundary."""
    repository = _windows_root(repository_root) if repository_root is not None else None
    scan = None
    if scan_root is not None:
        scan = _windows_root(scan_root, repository)

    raw = PureWindowsPath(ntpath.normpath(path))
    if scan is not None:
        # Checkov's leading slash means "relative to the scan root". A drive
        # qualified path, however, is an actual absolute path and can only be
        # accepted when it falls under the repository.
        if path.startswith("/") and not _is_windows_absolute(path):
            candidate = scan / path.lstrip("/")
        elif raw.is_absolute():
            candidate = raw
        else:
            candidate = scan / raw
    elif repository is not None:
        if path.startswith("/") and not _is_windows_absolute(path):
            candidate = repository / path.lstrip("/")
        elif raw.is_absolute():
            candidate = raw
        else:
            candidate = repository / raw
    else:
        candidate = raw

    boundary = repository or scan
    if boundary is not None:
        candidate = PureWindowsPath(ntpath.normpath(candidate.as_posix()))
        try:
            relative = candidate.relative_to(boundary)
        except ValueError:
            return None
        return relative.as_posix()

    # With no root context, keep the historical behavior but make a path
    # traversal harmless by declining to emit it.
    relative_path = ntpath.normpath(candidate.as_posix()).replace("\\", "/").lstrip("/")
    if relative_path == ".." or relative_path.startswith("../"):
        return None
    return relative_path


def _posix_artifact_path(
    path: str,
    scan_root: object | None,
    repository_root: object | None,
) -> str | None:
    """Return a POSIX artifact path relative to the repository boundary."""
    repository = None
    if repository_root is not None:
        repository = _posix_root(repository_root)
    scan = None
    if scan_root is not None:
        scan = _posix_root(scan_root, repository)

    if scan is not None:
        if path.startswith("/"):
            absolute = Path(path).resolve(strict=False)
            # A real absolute Checkov path should remain absolute only when it
            # is already inside a known root. Otherwise a leading slash is the
            # conventional Checkov spelling for a scan-root-relative path.
            if _is_within(absolute, scan) or (
                repository is not None and _is_within(absolute, repository)
            ):
                candidate = absolute
            else:
                candidate = (scan / path.lstrip("/")).resolve(strict=False)
        else:
            candidate = (scan / path).resolve(strict=False)
    elif repository is not None:
        if path.startswith("/"):
            absolute = Path(path).resolve(strict=False)
            if _is_within(absolute, repository):
                candidate = absolute
            else:
                candidate = (repository / path.lstrip("/")).resolve(strict=False)
        else:
            candidate = (repository / path).resolve(strict=False)
    else:
        # There is no boundary to relativize against. Normalize to a relative
        # path rather than emitting a leading slash or traversal component.
        relative = posixpath.normpath(path.lstrip("/"))
        if relative in ("", "."):
            return ""
        if relative == ".." or relative.startswith("../"):
            return None
        return relative

    boundary = repository or scan
    if boundary is None or not _is_within(candidate, boundary):
        return None
    return candidate.relative_to(boundary).as_posix()


def _artifact_uri(
    file_path: object,
    scan_root: object | None = None,
    repository_root: object | None = None,
) -> str | None:
    """Encode a Checkov path as a repository-relative URI-reference.

    Checkov reports source paths such as ``/iam.tf`` relative to the directory
    it scanned. When roots are supplied, resolve that convention first and
    then express the result relative to the repository root. A path outside
    the repository returns ``None`` so callers can retain the result without
    publishing an unsafe ``../`` or absolute location.
    """
    path = _path_text(file_path)
    windows_context = any(
        value is not None and _is_windows_absolute(_path_text(value))
        for value in (scan_root, repository_root, path)
    )
    if windows_context:
        relative = _windows_artifact_path(path, scan_root, repository_root)
    else:
        relative = _posix_artifact_path(path, scan_root, repository_root)
    if relative is None:
        return None
    # Keep path separators, and the Windows drive colon when no root context
    # is available, but encode spaces and URI delimiters such as '#' and '?'.
    return quote(relative, safe="/:@")


def _valid_line_range(file_line_range: object) -> tuple[int, int] | None:
    """Return a valid SARIF line range, or ``None`` for malformed input."""
    if not isinstance(file_line_range, (list, tuple)) or len(file_line_range) != 2:
        return None
    start, end = file_line_range
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (start, end)):
        return None
    if start < 1 or end < start:
        return None
    return start, end


def _physical_location(
    file_path: str,
    file_line_range: object,
    scan_root: object | None = None,
    repository_root: object | None = None,
) -> dict[str, Any] | None:
    artifact_uri = _artifact_uri(file_path, scan_root, repository_root)
    if artifact_uri is None:
        return None
    location: dict[str, Any] = {
        "artifactLocation": {"uri": artifact_uri},
    }
    # Checkov emits [start, end]. Invalid, zero, negative, reversed, short,
    # or non-integer ranges deliberately degrade to a file-level location.
    line_range = _valid_line_range(file_line_range)
    if line_range:
        location["region"] = {
            "startLine": line_range[0],
            "endLine": line_range[1],
        }
    return {"physicalLocation": location}


def build_sarif(
    enriched: list[EnrichedFinding],
    unmapped: list[dict[str, Any]] | None = None,
    version: str = "0.0.0",
    target: str | None = None,
    scan_root: object | None = None,
    repository_root: object | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from enriched (and unmapped) findings.

    Args:
        enriched: Findings with registry mappings — these carry the
            article/severity/remediation metadata.
        unmapped: Raw Checkov finding dicts with no registry entry,
            included as ``note``-level results tagged ``mapped: false``.
        version: tf-eu-guard version for ``tool.driver.version``.
        target: The scanned path, recorded in ``run.invocations`` for
            provenance.
        scan_root: Directory Checkov scanned. Checkov's leading-slash source
            paths are resolved relative to this root.
        repository_root: Checkout root used to make artifact locations
            repository-relative. Findings outside this root retain their
            result metadata but have no physical location.

    Returns:
        A SARIF 2.1.0 document as a plain dict, ready to serialize.
    """
    enriched = sort_findings(enriched)
    unmapped = sort_unmapped_findings(unmapped or [])

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    def _rule_for(check_id: str, finding: EnrichedFinding) -> int:
        if check_id in rule_index:
            return rule_index[check_id]
        rule: dict[str, Any] = {
            "id": check_id,
            "properties": {
                "mapped": True,
                "severity": finding.severity.value,
                "articles": _articles_property(finding),
                "remediation": finding.remediation,
            },
        }
        if finding.check_name:
            rule["shortDescription"] = {"text": finding.check_name}
        if finding.risk_explanation:
            rule["fullDescription"] = {"text": finding.risk_explanation}
        guideline = safe_guideline(finding.guideline)
        if guideline:
            rule["helpUri"] = guideline
        rule_index[check_id] = len(rules)
        rules.append(rule)
        return rule_index[check_id]

    def _unmapped_rule(check: dict[str, Any]) -> int:
        check_id = _required_check_id(check.get("check_id"))
        if check_id in rule_index:
            return rule_index[check_id]
        rule: dict[str, Any] = {
            "id": check_id,
            "properties": {"mapped": False},
        }
        if check.get("check_name"):
            rule["shortDescription"] = {"text": check["check_name"]}
        rule_index[check_id] = len(rules)
        rules.append(rule)
        return rule_index[check_id]

    # Build the rule registry before results. Rule indexes are then a lookup
    # derived from the sorted, complete rule set rather than a stale position.
    mapped_by_id = {_required_check_id(finding.check_id): finding for finding in enriched}
    unmapped_by_id = {_required_check_id(check.get("check_id")): check for check in unmapped}
    for check_id in sorted(set(mapped_by_id) | set(unmapped_by_id)):
        if check_id in mapped_by_id:
            _rule_for(check_id, mapped_by_id[check_id])
        else:
            _unmapped_rule(unmapped_by_id[check_id])

    results: list[dict[str, Any]] = []
    entries: list[tuple[str, EnrichedFinding | dict[str, Any]]] = sorted(
        [("mapped", finding) for finding in enriched] + [("unmapped", check) for check in unmapped],
        key=lambda entry: (
            finding_sort_key(cast(EnrichedFinding, entry[1]))
            if entry[0] == "mapped"
            else unmapped_sort_key(cast(dict[str, Any], entry[1]))
        ),
    )
    for kind, item in entries:
        if kind == "mapped":
            finding = cast(EnrichedFinding, item)
            check_id = _required_check_id(finding.check_id)
            index = rule_index[check_id]
            location = _physical_location(
                finding.file_path,
                finding.file_line_range,
                scan_root,
                repository_root,
            )
            guideline = safe_guideline(finding.guideline)
            results.append(
                {
                    "ruleId": check_id,
                    "ruleIndex": index,
                    "level": sarif_level(finding.severity),
                    "message": {"text": finding.risk_explanation or finding.check_name},
                    "locations": [location] if location is not None else [],
                    "properties": {
                        "mapped": True,
                        "resource": finding.resource,
                        "severity": finding.severity.value,
                        "articles": _articles_property(finding),
                        "remediation": finding.remediation,
                        **({"guideline": guideline} if guideline else {}),
                    },
                }
            )
            continue

        check = cast(dict[str, Any], item)
        check_id = _required_check_id(check.get("check_id"))
        index = rule_index[check_id]
        location = _physical_location(
            check.get("file_path", ""),
            check.get("file_line_range", []),
            scan_root,
            repository_root,
        )
        results.append(
            {
                "ruleId": check_id,
                "ruleIndex": index,
                "level": "note",
                "message": {
                    "text": (
                        f"{check.get('check_name', check_id)} — no current EU "
                        f"regulatory mapping (surfaced for visibility, does not "
                        f"affect severity gating)."
                    )
                },
                "locations": [location] if location is not None else [],
                "properties": {
                    "mapped": False,
                    "resource": check.get("resource"),
                },
            }
        )

    invocation: dict[str, Any] = {"executionSuccessful": True}
    if target:
        invocation["commandLine"] = f"tf-eu-guard scan {target}"

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tf-eu-guard",
                        "version": version,
                        "informationUri": "https://github.com/44aayush/tf-eu-guard",
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
