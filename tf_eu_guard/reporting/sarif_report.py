"""SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.

Each finding becomes a SARIF ``result`` whose ``ruleId`` is the Checkov
check ID; the registry's regulatory context (NIS2/GDPR articles, severity,
remediation) rides along in ``properties`` on both the ``tool.driver.rules``
entry and the per-result ``properties``. Code Scanning renders each rule's
``help`` (remediation and article list), ``properties.tags`` (framework and
article labels, filterable) and ``properties.security-severity`` (ranking);
the custom ``properties`` themselves are for other SARIF consumers. Unmapped Checkov findings are
included as low-visibility ``note``-level results tagged
``properties.mapped = false`` rather than silently dropped — the same
surface-them-anywhere policy the HTML and JSON reports follow.

The output is validated against the official OASIS SARIF 2.1.0 JSON Schema
in ``tests/test_sarif_report.py`` (schema vendored under
``tests/schemas/``), not just eyeballed.
"""

import hashlib
import ntpath
import posixpath
import re
from pathlib import Path, PureWindowsPath
from typing import Any, cast
from urllib.parse import quote

from tf_eu_guard.models import EnrichedFinding, Severity, Waiver
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


#: GitHub Code Scanning ranks alerts by ``properties.security-severity``, a
#: string holding a CVSS-like 0.0-10.0 score. GitHub's bands are critical
#: > 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9; each value below sits
#: inside its band. Rules with no registry mapping carry no
#: ``security-severity`` at all (they have no registry severity, and are
#: ``note``-level), so GitHub falls back to ranking them by ``level``.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}

#: ``partialFingerprints`` key; the suffix is the hash recipe version.
FINGERPRINT_KEY = "tfEuGuard/v1"

#: File-level fallback location for results whose source file is outside
#: the repository (``locations`` is required by GitHub for every result).
ROOT_URI_BASE_ID = "%SRCROOT%"

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~&])")


def _md_escape(text: str) -> str:
    """Backslash-escape Markdown and HTML-significant characters in *text*."""
    return _MD_SPECIAL.sub(r"\\\1", text)


def _outside_path_key(
    file_path: object, scan_root: object | None, repository_root: object | None
) -> str:
    """Fingerprint path for a file outside the repository.

    Relative to the scan root when one is known (stable across machines);
    otherwise the basename plus a hash of the normalized absolute path, so
    two different outside files never collide.
    """
    text = _path_text(file_path)
    if scan_root is not None and not _is_windows_absolute(_path_text(scan_root)):
        repo = _posix_root(repository_root) if repository_root is not None else None
        scan = _posix_root(scan_root, repo)
        candidate = Path(text) if text.startswith("/") else scan / text
        resolved = Path(posixpath.normpath(str(candidate)))
        return "outside:" + posixpath.relpath(str(resolved), str(scan))
    normalized = posixpath.normpath(text)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"outside:{posixpath.basename(normalized)}:{digest}"


def _fingerprint(check_id: str, resource: object, artifact_uri: str | None) -> str:
    """Stable sha256 of check ID, resource and repo-relative path.

    A result outside the repository hashes an empty path: an absolute or
    ``../`` path would differ per machine and defeat the stability.
    """
    material = "\n".join((check_id, str(resource or ""), artifact_uri or ""))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _rule_help(finding: EnrichedFinding) -> dict[str, str]:
    """``help`` with plain-text and Markdown remediation plus article list."""
    articles = _articles_property(finding)
    remediation = finding.remediation or ""
    text_parts = []
    md_parts = []
    if remediation:
        text_parts.append(f"Remediation: {remediation}")
        md_parts.append(f"**Remediation**\n\n{_md_escape(remediation)}")
    if articles:
        text_parts.append("Regulatory references: " + "; ".join(articles))
        md_parts.append(
            "**Regulatory references**\n\n" + "\n".join(f"- {_md_escape(a)}" for a in articles)
        )
    if not text_parts:
        text_parts.append(finding.check_name or finding.check_id)
        md_parts.append(_md_escape(finding.check_name or finding.check_id))
    return {"text": "\n\n".join(text_parts), "markdown": "\n\n".join(md_parts)}


def _rule_tags(finding: EnrichedFinding) -> list[str]:
    """``security``, then framework names, then article labels."""
    tags = ["security"]
    for article in sorted_articles(finding):
        if article.framework.value not in tags:
            tags.append(article.framework.value)
    for label in _articles_property(finding):
        if label not in tags:
            tags.append(label)
    return tags


def _suppressions(
    suppressed: bool, reason: str | None, waiver: Waiver | None = None
) -> dict[str, Any]:
    """Return the ``suppressions`` result member for an inline-skipped or waived check."""
    entries: list[dict[str, Any]] = []
    if suppressed:
        suppression: dict[str, Any] = {"kind": "inSource"}
        if reason:
            suppression["justification"] = reason
        entries.append(suppression)
    if waiver:
        entries.append(
            {
                "kind": "external",
                "status": "accepted",
                "justification": f"{waiver.reason} (owner {waiver.owner}, "
                f"expires {waiver.expires.isoformat()})",
            }
        )
    return {"suppressions": entries} if entries else {}


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


def _root_location() -> dict[str, Any]:
    """File-level location at the repository root, for out-of-repo files."""
    return {"physicalLocation": {"artifactLocation": {"uri": ".", "uriBaseId": ROOT_URI_BASE_ID}}}


def build_sarif(
    enriched: list[EnrichedFinding],
    unmapped: list[dict[str, Any]] | None = None,
    version: str = "0.0.0",
    target: str | None = None,
    scan_root: object | None = None,
    repository_root: object | None = None,
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    baselined_unmapped: list[dict[str, Any]] | None = None,
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
            result metadata but get a file-level location at the repository root
            (``uri: "."`` with ``uriBaseId: %SRCROOT%``).
        suppressed: Mapped findings suppressed by inline ``checkov:skip``
            comments. They become results carrying a SARIF ``suppressions``
            entry of kind ``inSource`` (with the stated reason as
            ``justification`` when one was given).
        suppressed_unmapped: Raw Checkov dicts for suppressed unmapped checks,
            handled the same way.
        waived: Mapped findings accepted by the waiver file. They become
            results carrying an ``external`` / ``accepted`` suppression whose
            justification names the reason, owner and expiry.
        baselined: Mapped findings already in the ``--baseline`` report
            (``baselineState: "unchanged"``). ``None`` means no baseline was
            used; otherwise active mapped results are ``baselineState: "new"``.
        baselined_unmapped: Unmapped findings already in the baseline, handled the
            same way (``unchanged``; other active unmapped results are ``new``).

    Returns:
        A SARIF 2.1.0 document as a plain dict, ready to serialize.
    """
    known = {id(f) for f in baselined or []}
    enriched = sort_findings([*enriched, *(suppressed or []), *(waived or []), *(baselined or [])])
    known_unmapped = {id(c) for c in baselined_unmapped or []}
    unmapped = sort_unmapped_findings(
        [*(unmapped or []), *(suppressed_unmapped or []), *(baselined_unmapped or [])]
    )

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
                "tags": _rule_tags(finding),
                "security-severity": SECURITY_SEVERITY[finding.severity],
            },
            "help": _rule_help(finding),
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
            "properties": {"mapped": False, "tags": ["security"]},
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
            artifact_uri = _artifact_uri(finding.file_path, scan_root, repository_root)
            if artifact_uri is None:
                artifact_uri = _outside_path_key(finding.file_path, scan_root, repository_root)
            results.append(
                {
                    "ruleId": check_id,
                    "ruleIndex": index,
                    "level": sarif_level(finding.severity),
                    "message": {"text": finding.risk_explanation or finding.check_name},
                    "locations": [location if location is not None else _root_location()],
                    "partialFingerprints": {
                        FINGERPRINT_KEY: _fingerprint(check_id, finding.resource, artifact_uri)
                    },
                    **_suppressions(finding.suppressed, finding.suppression_reason, finding.waiver),
                    **(
                        {"baselineState": "unchanged" if id(finding) in known else "new"}
                        if baselined is not None and not (finding.suppressed or finding.waiver)
                        else {}
                    ),
                    "properties": {
                        "mapped": True,
                        "resource": finding.resource,
                        "severity": finding.severity.value,
                        "articles": _articles_property(finding),
                        "remediation": finding.remediation,
                        **({"locationOutsideRepository": True} if location is None else {}),
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
        artifact_uri = _artifact_uri(check.get("file_path", ""), scan_root, repository_root)
        if artifact_uri is None:
            artifact_uri = _outside_path_key(check.get("file_path", ""), scan_root, repository_root)
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
                "locations": [location if location is not None else _root_location()],
                "partialFingerprints": {
                    FINGERPRINT_KEY: _fingerprint(check_id, check.get("resource"), artifact_uri)
                },
                **_suppressions(bool(check.get("suppressed")), check.get("suppression_reason")),
                **(
                    {"baselineState": "unchanged" if id(check) in known_unmapped else "new"}
                    if baselined_unmapped is not None and not check.get("suppressed")
                    else {}
                ),
                "properties": {
                    "mapped": False,
                    "resource": check.get("resource"),
                    **({"locationOutsideRepository": True} if location is None else {}),
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
                "properties": {"weakeningSettings": list(weakening_settings or [])},
            }
        ],
    }
