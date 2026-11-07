"""Stable ordering helpers shared by report generators.

Checkov does not promise an ordering for its result collections.  Keeping the
ordering policy here means every report format sees the same deterministic
input without mutating the caller's list.
"""

from __future__ import annotations

import json
from math import inf
from typing import Any

from tf_eu_guard.models import EnrichedFinding


def _line_numbers(value: object) -> tuple[int | float, int | float]:
    """Return a comparable ``(start, end)`` pair for a Checkov line range."""
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        start, end = value[0], value[1]
        if (
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
        ):
            return start, end
    if isinstance(value, (list, tuple)) and value:
        line = value[0]
        if isinstance(line, int) and not isinstance(line, bool):
            return line, line
    return inf, inf


def finding_sort_key(finding: EnrichedFinding) -> tuple[Any, ...]:
    """Sort a finding by location, identity, and then all remaining fields.

    The first fields are intentionally the user-facing stable key: file path,
    start line, Checkov ID, and resource.  The remaining fields make otherwise
    tied records deterministic as well.
    """
    start, end = _line_numbers(finding.file_line_range)
    articles = tuple(
        sorted(
            (
                str(article.framework.value),
                str(article.article),
                str(article.title),
            )
            for article in finding.articles
        )
    )
    return (
        str(finding.file_path or "").replace("\\", "/"),
        start,
        end,
        str(finding.check_id or ""),
        str(finding.resource or ""),
        str(finding.check_name or ""),
        str(getattr(finding.severity, "value", finding.severity) or ""),
        articles,
        str(finding.guideline or ""),
        str(finding.risk_explanation or ""),
        str(finding.remediation or ""),
    )


def sort_findings(findings: list[EnrichedFinding]) -> list[EnrichedFinding]:
    """Return findings in deterministic order without changing the input list."""
    return sorted(findings, key=finding_sort_key)


def unmapped_sort_key(check: dict[str, Any]) -> tuple[Any, ...]:
    """Return the corresponding deterministic key for a raw Checkov finding."""
    start, end = _line_numbers(check.get("file_line_range"))
    # JSON with sorted keys is a deterministic final tie-breaker for any custom
    # fields Checkov may add to a raw result.
    serialized = json.dumps(check, sort_keys=True, default=str, separators=(",", ":"))
    return (
        str(check.get("file_path") or "").replace("\\", "/"),
        start,
        end,
        str(check.get("check_id") or ""),
        str(check.get("resource") or ""),
        str(check.get("check_name") or ""),
        serialized,
    )


def sort_unmapped_findings(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return raw unmapped Checkov findings in deterministic order."""
    return sorted(checks, key=unmapped_sort_key)


def sorted_articles(finding: EnrichedFinding):
    """Return article references in a stable presentation order."""
    return sorted(
        finding.articles,
        key=lambda article: (
            str(article.framework.value),
            str(article.article),
            str(article.title),
        ),
    )
