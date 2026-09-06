"""Tests keeping the supported-Python-version claims in sync.

The version floor lives in five places that must agree: pyproject's
``requires-python``, its trove classifiers, the CI test matrix, the README
badge, and install_and_test.sh's ``MIN_PY``. Packaging metadata drifting from
the CI matrix is exactly how a version gets "supported" in the badge but never
actually tested (or tested but rejected at install time) — the same class of
silent drift tools/check_doc_counts.py exists to catch for mapping counts.
"""

import re
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def _classifier_versions(project: dict) -> list[str]:
    prefix = "Programming Language :: Python :: "
    return sorted(
        line[len(prefix):]
        for line in project["classifiers"]
        if line.startswith(prefix) and line[len(prefix):].count(".") == 1
    )


def _ci_matrix_versions() -> list[str]:
    workflow = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return sorted(workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"])


def test_requires_python_floor_matches_lowest_classifier():
    """The floor must be exactly the lowest version we claim to support."""
    project = _pyproject()["project"]
    versions = _classifier_versions(project)
    assert versions, "no Python version classifiers found"
    assert project["requires-python"] == f">={versions[0]}"


def test_ci_matrix_matches_packaging_classifiers():
    """Every classifier version is tested in CI, and CI tests nothing unclaimed."""
    assert _ci_matrix_versions() == _classifier_versions(_pyproject()["project"])


def test_ci_matrix_actually_runs_each_supported_version():
    """Sanity: the matrix is non-empty and holds plain '3.x' strings."""
    matrix = _ci_matrix_versions()
    assert matrix, "CI test matrix is empty"
    assert all(re.fullmatch(r"3\.\d+", v) for v in matrix)


def test_readme_badge_matches_requires_python_floor():
    floor = _pyproject()["project"]["requires-python"].lstrip(">=")
    readme = (REPO_ROOT / "README.md").read_text()
    assert f"![Python {floor}+]" in readme, "README badge disagrees with requires-python"
    assert f"Python ≥ {floor}" in readme, "README requirement text disagrees with requires-python"


def test_install_script_floor_matches_requires_python():
    floor = _pyproject()["project"]["requires-python"].lstrip(">=")
    script = (REPO_ROOT / "install_and_test.sh").read_text()
    assert f'MIN_PY="{floor}"' in script, "install_and_test.sh MIN_PY disagrees with requires-python"
