"""Shared helpers for CLI integration tests."""

from pathlib import Path

from tf_eu_guard.cli import main

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"
PLAN_FIXTURE = "tests/fixtures/checkov-vulnerable-plan.json"
K8S_FIXTURE = "tests/fixtures/checkov-vulnerable-k8s.json"
REGION_FIXTURE = "tests/fixtures/region-aliases"
SECRET_SHAPES_FIXTURE = "tests/fixtures/secret-shapes"


def run_cli(monkeypatch, tmp_path: Path, *arguments):
    """Invoke the CLI with ``arguments`` from ``tmp_path``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", *arguments])
    return main()
