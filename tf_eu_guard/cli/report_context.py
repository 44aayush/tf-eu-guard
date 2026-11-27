"""The scan result as the report layer consumes it."""

import argparse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from tf_eu_guard.mapping.coverage import RequirementResult
from tf_eu_guard.mapping.loader import LoadedRegistry
from tf_eu_guard.models import EnrichedFinding

if TYPE_CHECKING:
    from tf_eu_guard.cli.pipeline import ScanFindings


@dataclass(frozen=True)
class ReportContext:
    """Everything a report format reads, passed as one value.

    ``baselined`` holds the known findings whether or not ``--baseline`` was given
    (it is empty without one); use ``known_findings`` where "no baseline used" must
    stay distinguishable from "baseline matched nothing".
    """

    args: argparse.Namespace
    findings: list[EnrichedFinding]
    unmapped: list[dict[str, Any]]
    suppressed: list[EnrichedFinding] = field(default_factory=list)
    suppressed_unmapped: list[dict[str, Any]] = field(default_factory=list)
    waived: list[EnrichedFinding] = field(default_factory=list)
    baselined: list[EnrichedFinding] = field(default_factory=list)
    checkov_version: str | None = None
    requirements: list[RequirementResult] = field(default_factory=list)
    registry: LoadedRegistry | None = None
    weakening_settings: list[str] = field(default_factory=list)
    provenance: dict[str, Any] | None = None

    @classmethod
    def from_result(cls, args: argparse.Namespace, result: "ScanFindings") -> "ReportContext":
        """Copy the report-relevant fields of a scan result."""
        return cls(
            args=args,
            findings=result.findings,
            unmapped=result.unmapped,
            suppressed=result.suppressed,
            suppressed_unmapped=result.suppressed_unmapped,
            waived=result.waived,
            baselined=result.baselined,
            checkov_version=result.checkov_version,
            requirements=result.requirements,
            registry=result.registry,
            weakening_settings=result.weakening_settings,
            provenance=result.provenance,
        )

    @property
    def target(self) -> str:
        """The scanned path, or ``checkov-json:<file>`` for a saved Checkov run."""
        args = self.args
        return str(args.path) if args.path else f"checkov-json:{args.checkov_json}"

    @property
    def known_findings(self) -> list[EnrichedFinding] | None:
        """The baselined findings, or None when no ``--baseline`` was given."""
        return self.baselined if self.args.baseline else None

    @property
    def suppressed_total(self) -> int:
        """Suppressed findings, mapped and unmapped."""
        return len(self.suppressed) + len(self.suppressed_unmapped)

    @property
    def shown_unmapped(self) -> list[dict[str, Any]] | None:
        """The unmapped list when ``--show-unmapped`` is set, else None."""
        return self.unmapped if getattr(self.args, "show_unmapped", False) else None
