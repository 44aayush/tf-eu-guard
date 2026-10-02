"""tf-eu-guard: EU compliance security linter for Terraform."""

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the single source of truth; installed callers obtain
    # the version from the distribution metadata generated from it.
    __version__ = version("tf-eu-guard")
except PackageNotFoundError:  # pragma: no cover - source tree before install
    __version__ = "0+unknown"
