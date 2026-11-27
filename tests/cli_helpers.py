"""Shared helpers for CLI integration tests."""

import os
from pathlib import Path

from tf_eu_guard.cli import main

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"
PLAN_FIXTURE = "tests/fixtures/checkov-vulnerable-plan.json"
K8S_FIXTURE = "tests/fixtures/checkov-vulnerable-k8s.json"
REGION_FIXTURE = "tests/fixtures/region-aliases"
SECRET_SHAPES_FIXTURE = "tests/fixtures/secret-shapes"


def clean_git_env() -> dict[str, str]:
    """os.environ without any GIT_* variable, plus no user/system git config.

    An exported GIT_DIR would otherwise make a test's ``git -C <tmp> commit`` write into
    another repository.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    return env


def run_cli(monkeypatch, tmp_path: Path, *arguments):
    """Invoke the CLI with ``arguments`` from ``tmp_path``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", *arguments])
    return main()


def run_command(monkeypatch, tmp_path: Path, *argv) -> int:
    """Invoke the CLI with ``argv`` as-is (no implicit ``scan``)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", *argv])
    return main()
