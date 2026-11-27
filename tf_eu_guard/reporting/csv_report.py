"""CSV report: one row per finding x article."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING, Any

from tf_eu_guard.reporting.sorting import (
    sort_findings,
    sort_unmapped_findings,
    sorted_articles,
)
from tf_eu_guard.reporting.untrusted import sanitize

if TYPE_CHECKING:
    from tf_eu_guard.cli.pipeline import ScanFindings

COLUMNS = (
    "status,severity,check_id,check_name,resource,file_path,line_start,line_end,"
    "framework,article,article_title,risk,remediation,suppression_reason,"
    "waiver_owner,waiver_expires"
).split(",")


def _cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas (OWASP CSV injection)."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _u(value: Any) -> str:
    """Escape control characters in a value taken from the scanned checkout."""
    return sanitize(value)


def _lines(finding_or_check: Any) -> tuple[Any, Any]:
    rng = list(finding_or_check or [])
    return (rng[0], rng[1] if len(rng) > 1 else rng[0]) if rng else ("", "")


def render_csv(result: ScanFindings) -> str:
    """Render all findings, including suppressed, waived, baselined and unmapped."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    groups = (
        ("active", result.findings),
        ("suppressed", result.suppressed),
        ("waived", result.waived),
        ("baselined", result.baselined),
    )
    for status, findings in groups:
        for f in sort_findings(findings):
            start, end = _lines(f.file_line_range)
            waiver = f.waiver
            base = [
                status, f.severity.value, _u(f.check_id), _u(f.check_name), _u(f.resource),
                _u(f.file_path), start, end,
            ]  # fmt: skip
            tail = [
                f.risk_explanation, f.remediation, _u(f.suppression_reason),
                _u(waiver.owner) if waiver else "",
                waiver.expires.isoformat() if waiver else "",
            ]  # fmt: skip
            for a in sorted_articles(f) or [None]:
                art = [a.framework.value, a.article, a.title] if a else ["", "", ""]
                writer.writerow([_cell(c) for c in [*base, *art, *tail]])
    unmapped = [("unmapped", c) for c in sort_unmapped_findings(result.unmapped)]
    unmapped += [("suppressed", c) for c in sort_unmapped_findings(result.suppressed_unmapped)]
    for status, check in unmapped:
        start, end = _lines(check.get("file_line_range"))
        row = [
            status, "", _u(check.get("check_id")), _u(check.get("check_name")),
            _u(check.get("resource")), _u(check.get("file_path")), start, end,
            "", "", "", "", "", _u(check.get("suppression_reason")), "", "",
        ]  # fmt: skip
        writer.writerow([_cell(c) for c in row])
    return buffer.getvalue()
