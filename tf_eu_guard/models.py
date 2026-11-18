"""Data models for compliance findings and reports."""

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Framework(StrEnum):
    """Regulatory frameworks and project policy scopes used in reports."""

    NIS2 = "NIS2"
    GDPR = "GDPR"
    POLICY = "POLICY"


@dataclass
class ArticleReference:
    """Reference to a specific compliance framework article."""

    framework: Framework
    article: str  # e.g. "Art. 21(2)(f)"
    title: str  # Human-readable article title


@dataclass
class ComplianceMapping:
    """Maps a Checkov check to EU compliance requirements."""

    check_id: str
    check_name: str
    articles: list[ArticleReference]
    risk_explanation: str
    remediation: str
    severity: Severity


@dataclass(frozen=True)
class Waiver:
    """A reviewed acceptance of one mapped finding (see ``tf_eu_guard.waivers``)."""

    check_id: str
    resource: str
    owner: str
    reason: str
    expires: date
    file: str | None = None


@dataclass
class EnrichedFinding:
    """A Checkov finding enriched with EU compliance context."""

    check_id: str
    check_name: str
    resource: str
    file_path: str
    file_line_range: list[int]
    guideline: str | None

    # EU compliance enrichment
    articles: list[ArticleReference] = field(default_factory=list)
    risk_explanation: str = ""
    remediation: str = ""
    severity: Severity = Severity.MEDIUM

    # Inline suppression (``#checkov:skip=ID:reason`` / ``checkov.io/skip``).
    # Suppressed findings are reported but never counted as active findings.
    suppressed: bool = False
    suppression_reason: str | None = None

    # Set when an unexpired waiver from the waiver file covers this finding.
    waiver: Waiver | None = None

    @property
    def frameworks(self) -> set[Framework]:
        """Return unique frameworks referenced by this finding."""
        return {article.framework for article in self.articles}
