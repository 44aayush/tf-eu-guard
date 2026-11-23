"""tf-eu-guard: EU compliance security linter for Terraform."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

try:
    # pyproject.toml is the single source of truth; installed callers obtain
    # the version from the distribution metadata generated from it.
    __version__ = version("tf-eu-guard")
except PackageNotFoundError:  # pragma: no cover - source tree before install
    __version__ = "0+unknown"

#: JSON Schema of ``--output json --json-format object``, shipped in the wheel.
REPORT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "report.schema.json"

__all__ = ["REPORT_SCHEMA_PATH", "ScanResult", "__version__", "scan"]

if TYPE_CHECKING:
    from tf_eu_guard.api import ScanResult, scan


def __getattr__(name: str) -> object:
    """Lazy public API so ``import tf_eu_guard`` stays cheap and cycle-free."""
    if name in ("scan", "ScanResult"):
        from tf_eu_guard import api

        return getattr(api, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
