"""Uniform presentation of findings suppressed by inline Checkov comments.

Mapped suppressed findings are :class:`EnrichedFinding` objects; unmapped ones
stay raw Checkov dicts, exactly like unmapped active findings. Reports show
both kinds in one list, so this module flattens them into one record type
with a deterministic order.
"""

from dataclasses import dataclass
from typing import Any

from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.html_common import esc
from tf_eu_guard.reporting.sorting import _line_numbers

#: Wording used wherever a skip comment carries no reason.
NO_REASON_TEXT = "no reason given"


@dataclass(frozen=True)
class SuppressedItem:
    """One suppressed check, mapped or unmapped, ready for display."""

    check_id: str
    check_name: str
    resource: str
    file_path: str
    file_line_range: list[int]
    reason: str | None
    mapped: bool
    finding: EnrichedFinding | None = None

    @property
    def reason_text(self) -> str:
        """The stated reason, or ``no reason given``."""
        return self.reason or NO_REASON_TEXT

    @property
    def lines(self) -> str | None:
        """``start-end`` line text, or ``None`` when Checkov gave no anchor."""
        numbers = self.file_line_range or []
        if len(numbers) >= 2 and (numbers[0] or numbers[1]):
            return f"{numbers[0]}-{numbers[1]}"
        if len(numbers) == 1 and numbers[0]:
            return str(numbers[0])
        return None

    @property
    def location(self) -> str:
        """Plain ``file:lines`` text (not escaped)."""
        return f"{self.file_path}:{self.lines}" if self.lines else str(self.file_path)


def suppressed_items(
    suppressed: list[EnrichedFinding] | None,
    suppressed_unmapped: list[dict[str, Any]] | None,
) -> list[SuppressedItem]:
    """Flatten mapped and unmapped suppressed findings into sorted items."""
    items = [
        SuppressedItem(
            check_id=f.check_id,
            check_name=f.check_name,
            resource=f.resource,
            file_path=f.file_path,
            file_line_range=f.file_line_range,
            reason=f.suppression_reason,
            mapped=True,
            finding=f,
        )
        for f in suppressed or []
    ]
    items.extend(
        SuppressedItem(
            check_id=str(c.get("check_id") or ""),
            check_name=str(c.get("check_name") or ""),
            resource=str(c.get("resource") or ""),
            file_path=str(c.get("file_path") or ""),
            file_line_range=c.get("file_line_range") or [],
            reason=c.get("suppression_reason"),
            mapped=False,
        )
        for c in suppressed_unmapped or []
    )
    return sorted(
        items,
        key=lambda i: (
            i.file_path.replace("\\", "/"),
            *_line_numbers(i.file_line_range),
            i.check_id,
            i.resource,
            i.reason or "",
            not i.mapped,
        ),
    )


def suppressed_html(items: list[SuppressedItem]) -> str:
    """Render the shared HTML table of suppressed checks ('' when none)."""
    if not items:
        return ""
    rows = "\n".join(
        "<tr>"
        f"<td><code>{esc(i.check_id)}</code><br>{esc(i.check_name)}</td>"
        f"<td><code>{esc(i.resource)}</code></td>"
        f"<td><code>{esc(i.location)}</code></td>"
        f"<td>{esc(i.reason_text)}</td>"
        f"<td>{'mapped' if i.mapped else 'unmapped'}</td>"
        "</tr>"
        for i in items
    )
    return (
        '<section class="suppressed">\n'
        f"<h2>Suppressed by inline comment ({len(items)})</h2>\n"
        "<p>These checks failed but were suppressed with a <code>checkov:skip</code> "
        "comment or annotation in the scanned code. They are not counted as active "
        "findings and do not affect <code>--fail-on-severity</code> or "
        "<code>--fail-on-any</code>. Anyone who can edit the code can add such a "
        "comment, so review each one.</p>\n"
        '<table class="suppressed-table">\n'
        "<thead><tr><th>Check</th><th>Resource</th><th>Location</th>"
        "<th>Stated reason</th><th>EU mapping</th></tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n</table>\n</section>"
    )
