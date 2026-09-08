"""Packaging test: the built wheel must ship the mapping registries.

``pyproject.toml`` configures hatchling with ``packages = ["tf_eu_guard"]``,
so the four ``registry-*.yaml`` data files ride along inside the package
directory. Nothing else catches a future packaging-config change that
silently excluded them: the wheel would still install, the CLI would still
run, and every scan would degrade to unmapped findings — only at the
consumer. This test builds the actual wheel and inspects its contents.

Hermetic-adjacent: uses ``--no-isolation`` with the locally installed
hatchling (a ``dev`` extra), so the build needs no network. Skips when the
build tooling isn't installed; a *failed* build still fails the test —
that's the broken-packaging case it exists to catch.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

pytest.importorskip("build")
pytest.importorskip("hatchling")

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The registry data files that must ship inside the wheel, verbatim.
REGISTRY_FILES = (
    "registry-aws.yaml",
    "registry-azure.yaml",
    "registry-gcp.yaml",
    "registry-kubernetes.yaml",
)


def _build_wheel(tmp_path: Path) -> Path:
    """Build the project wheel (no isolation, no network) and return its path."""
    result = subprocess.run(
        [
            sys.executable, "-m", "build", "--wheel", "--no-isolation",
            "--outdir", str(tmp_path), str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "wheel build failed — if the packaging config is intact this is a "
        f"tooling problem, if not, this is exactly the failure to catch:\n"
        f"{result.stderr[-500:]}"
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


def test_wheel_ships_all_registry_yaml(tmp_path):
    """Every registry-*.yaml must be present inside the built wheel, non-empty
    and parseable — a packaging change that drops them fails here, in CI,
    instead of degrading every downstream scan to unmapped findings."""
    wheel = _build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
        for reg in REGISTRY_FILES:
            inner = f"tf_eu_guard/mapping/{reg}"
            assert inner in names, (
                f"{inner} missing from the wheel — the packaging config no "
                "longer ships the registries"
            )
            raw = zf.read(inner)
            assert raw, f"{inner} is empty inside the wheel"
            parsed = yaml.safe_load(raw)
            assert isinstance(parsed, dict) and parsed, (
                f"{inner} does not parse to a non-empty mapping"
            )


def test_wheel_ships_the_custom_checks(tmp_path):
    """The EUGUARD_* check modules are code, not data — but a packaging change
    could exclude the ``checks`` subpackage just as silently, and a scan
    without them simply loses the custom findings."""
    wheel = _build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
        for inner in (
            "tf_eu_guard/checks/gdpr/data_residency.py",
            "tf_eu_guard/checks/nis2/secrets_in_code.py",
            "tf_eu_guard/checks/k8s/secrets_in_code.py",
            "tf_eu_guard/checks/__init__.py",
        ):
            assert inner in names, f"{inner} missing from the wheel"
