"""Opt-in emulator tier: real Terraform against a LocalStack-compatible endpoint.

Every test here is skipped unless ``TFEG_RUN_EMULATOR=1`` and ``terraform`` is
on PATH. The endpoint comes from ``TFEG_EMULATOR_ENDPOINT``.
"""

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

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
    return os.environ.get("TFEG_EMULATOR_ENDPOINT", DEFAULT_ENDPOINT)


class Stack:
    """A fixture copied into a temporary directory with the emulator override."""

    def __init__(self, work: Path, env: dict[str, str]) -> None:
        self.work = work
        self.env = env

    def terraform(self, *args: str) -> str:
        done = subprocess.run(
            ["terraform", *args],
            cwd=self.work,
            env=self.env,
            check=True,
            capture_output=True,
            text=True,
        )
        return done.stdout

    def plan_json(self) -> Path:
        self.terraform("init", "-input=false", "-no-color")
        self.terraform("plan", "-input=false", "-no-color", "-out=tfplan")
        plan = self.work / "plan.json"
        plan.write_text(self.terraform("show", "-json", "tfplan"), encoding="utf-8")
        return plan

    def apply(self) -> None:
        self.terraform("apply", "-input=false", "-no-color", "-auto-approve", "tfplan")

    def destroy(self) -> None:
        self.terraform("destroy", "-input=false", "-no-color", "-auto-approve")


@pytest.fixture
def make_stack(tmp_path: Path, endpoint: str) -> Callable[[str, str], Stack]:
    def _make(fixture: str, region: str) -> Stack:
        work = tmp_path / "work"
        shutil.copytree(FIXTURES / fixture, work, ignore=shutil.ignore_patterns(".terraform"))
        override = OVERRIDE.read_text(encoding="utf-8").replace("@ENDPOINT@", endpoint)
        (work / "localstack_override.tf").write_text(override, encoding="utf-8")
        env = {**os.environ, "AWS_REGION": region, "TF_IN_AUTOMATION": "1"}
        env.pop("AWS_DEFAULT_REGION", None)
        return Stack(work, env)

    return _make
