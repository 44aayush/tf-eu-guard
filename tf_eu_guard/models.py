"""Data models for compliance findings and reports."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Framework(str, Enum):
    """Supported compliance frameworks."""
    NIS2 = "NIS2"
    GDPR = "GDPR"


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

    @property
    def frameworks(self) -> set[Framework]:
        """Return unique frameworks referenced by this finding."""
        return {article.framework for article in self.articles}


@dataclass
class ScanReport:
    """Complete scan report with metadata and findings."""
    target_path: str
    scan_timestamp: str
    checkov_version: str
    findings: list[EnrichedFinding]
    total_checks_run: int
    total_failed: int
    total_passed: int

    @property
    def by_severity(self) -> dict[Severity, list[EnrichedFinding]]:
        """Group findings by severity."""
        grouped: dict[Severity, list[EnrichedFinding]] = {
            severity: [] for severity in Severity
        }
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped

    @property
    def by_framework(self) -> dict[Framework, list[EnrichedFinding]]:
        """Group findings by framework."""
        grouped: dict[Framework, list[EnrichedFinding]] = {
            Framework.NIS2: [],
            Framework.GDPR: [],
        }
        for finding in self.findings:
            for framework in finding.frameworks:
                grouped[framework].append(finding)
        return grouped
