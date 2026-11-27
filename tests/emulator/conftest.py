"""Opt-in emulator tier: real Terraform against a LocalStack-compatible endpoint.

Every test here is skipped unless ``TFEG_RUN_EMULATOR=1`` and ``terraform`` is
on PATH. The endpoint comes from ``TFEG_EMULATOR_ENDPOINT``.
"""

import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from .stack import EmulatorUnavailable, Stack, emulator_env, require_endpoint

HERE = Path(__file__).resolve().parent
OVERRIDE = HERE / "localstack_override.tf"
FIXTURES = HERE / "fixtures"
DEFAULT_ENDPOINT = "http://127.0.0.1:4566"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TFEG_RUN_EMULATOR") != "1":
        reason = "emulator tier is opt-in: set TFEG_RUN_EMULATOR=1 (needs LocalStack and terraform)"
    elif shutil.which("terraform") is None:
        reason = "terraform is not on PATH"
    else:
        return
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if HERE in Path(str(item.path)).parents:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def endpoint() -> str:
    url = os.environ.get("TFEG_EMULATOR_ENDPOINT", DEFAULT_ENDPOINT)
    try:
        require_endpoint(url)
    except EmulatorUnavailable as exc:
        pytest.fail(str(exc), pytrace=False)
    return url


@pytest.fixture
def make_stack(tmp_path: Path, endpoint: str) -> Callable[[str, str], Stack]:
    def _make(fixture: str, region: str) -> Stack:
        work = tmp_path / "work"
        shutil.copytree(FIXTURES / fixture, work, ignore=shutil.ignore_patterns(".terraform"))
        override = OVERRIDE.read_text(encoding="utf-8").replace("@ENDPOINT@", endpoint)
        (work / "localstack_override.tf").write_text(override, encoding="utf-8")
        return Stack(work, emulator_env(region))

    return _make
