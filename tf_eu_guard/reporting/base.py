"""Base reporter interface."""

from abc import ABC, abstractmethod
from pathlib import Path

from tf_eu_guard.models import ScanReport


class BaseReporter(ABC):
    """Abstract base class for all report formats."""

    @abstractmethod
    def generate(self, report: ScanReport, output_path: Path | None = None) -> str:
        """
        Generate report from scan results.

        Args:
            report: Complete scan report with findings
            output_path: Optional path to write report file (if None, return as string)

        Returns:
            Report content as string
        """
        pass
