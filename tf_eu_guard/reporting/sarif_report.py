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

from typing import Any
from urllib.parse import quote

from tf_eu_guard.models import EnrichedFinding, Severity
from tf_eu_guard.reporting._html_common import safe_guideline

#: The OASIS SARIF 2.1.0 schema this output targets (what Code Scanning
#: ingests). Also the ``$schema`` value written into the document itself.
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
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
    return [f"{a.framework.value} {a.article}" for a in finding.articles]


def _artifact_uri(file_path: object) -> str:
    """Encode a Checkov filesystem path as a valid relative/file URI."""
    path = str(file_path or "").replace("\\", "/")
    # Keep path separators and a Windows drive colon, but encode characters
    # such as spaces, '#', and '?' that otherwise change URI interpretation.
    return quote(path, safe="/:@")


def _valid_line_range(file_line_range: object) -> tuple[int, int] | None:
    """Return a valid SARIF line range, or ``None`` for malformed input."""
    if not isinstance(file_line_range, (list, tuple)) or len(file_line_range) != 2:
        return None
    start, end = file_line_range
    if any(isinstance(value, bool) or not isinstance(value, int)
           for value in (start, end)):
        return None
    if start < 1 or end < start:
        return None
    return start, end


def _physical_location(file_path: str, file_line_range: object) -> dict[str, Any]:
    location: dict[str, Any] = {
        "artifactLocation": {"uri": _artifact_uri(file_path)},
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

    Returns:
        A SARIF 2.1.0 document as a plain dict, ready to serialize.
    """
    unmapped = unmapped or []

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

    results: list[dict[str, Any]] = []
    for finding in enriched:
        index = _rule_for(finding.check_id, finding)
        results.append({
            "ruleId": finding.check_id,
            "ruleIndex": index,
            "level": sarif_level(finding.severity),
            "message": {"text": finding.risk_explanation or finding.check_name},
            "locations": [
                _physical_location(finding.file_path, finding.file_line_range)
            ],
            "properties": {
                "mapped": True,
                "resource": finding.resource,
                "severity": finding.severity.value,
                "articles": _articles_property(finding),
                "remediation": finding.remediation,
                **({"guideline": safe_guideline(finding.guideline)}
                   if safe_guideline(finding.guideline) else {}),
            },
        })

    for check in unmapped:
        check_id = check.get("check_id", "UNKNOWN")
        if check_id not in rule_index:
            rule: dict[str, Any] = {
                "id": check_id,
                "properties": {"mapped": False},
            }
            if check.get("check_name"):
                rule["shortDescription"] = {"text": check["check_name"]}
            rule_index[check_id] = len(rules)
            rules.append(rule)
        results.append({
            "ruleId": check_id,
            "ruleIndex": rule_index[check_id],
            "level": "note",
            "message": {
                "text": (
                    f"{check.get('check_name', check_id)} — no current EU "
                    f"regulatory mapping (surfaced for visibility, does not "
                    f"affect severity gating)."
                )
            },
            "locations": [
                _physical_location(
                    check.get("file_path", ""),
                    check.get("file_line_range", []),
                )
            ],
            "properties": {
                "mapped": False,
                "resource": check.get("resource"),
            },
        })

    invocation: dict[str, Any] = {"executionSuccessful": True}
    if target:
        invocation["commandLine"] = f"tf-eu-guard scan {target}"

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
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
        }],
    }
