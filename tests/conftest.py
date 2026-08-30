"""Shared pytest fixtures for the tf-eu-guard test-suite.

Puts the repo root on ``sys.path`` so tests import ``tf_eu_guard`` even without
an editable install, and exposes the loaded registry plus a factory for
Checkov-shaped findings used by the enrichment tests.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def registry_path(repo_root: Path) -> Path:
    return repo_root / "tf_eu_guard" / "mapping"


@pytest.fixture(scope="session")
def registry(registry_path: Path):
    """The parsed compliance registry (check_id -> ComplianceMapping)."""
    from tf_eu_guard.mapping.loader import load_registry

    return load_registry(registry_path)


@pytest.fixture(scope="session")
def vulnerable_stack_dir(repo_root: Path) -> Path:
    return repo_root / "examples" / "vulnerable-aws"


@pytest.fixture
def sample_finding():
    """Return a factory that builds a Checkov-shaped failed-check dict.

    Mirrors the shape ``extract_failed_checks`` produces, so it can be fed
    straight into ``enrich_findings``.
    """

    def _make(
        check_id: str,
        *,
        check_name: str = "sample check",
        resource: str = "aws_x.y",
        file_path: str = "/main.tf",
        file_line_range=None,
        guideline=None,
    ) -> dict:
        return {
            "check_id": check_id,
            "check_name": check_name,
            "resource": resource,
            "file_path": file_path,
            "file_line_range": file_line_range or [1, 10],
            "guideline": guideline,
        }

    return _make
