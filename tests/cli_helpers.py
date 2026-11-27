"""Shared helpers for CLI integration tests."""

from pathlib import Path

from tf_eu_guard.cli import main

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"
PLAN_FIXTURE = "tests/fixtures/checkov-vulnerable-plan.json"
K8S_FIXTURE = "tests/fixtures/checkov-vulnerable-k8s.json"
REGION_FIXTURE = "tests/fixtures/region-aliases"
SECRET_SHAPES_FIXTURE = "tests/fixtures/secret-shapes"

#: A passed custom check. A gated `--checkov-json` scan rejects a file with no `EUGUARD_*` check
#: (TEG-09), so hand-built documents that feed a gate include it.
EUGUARD_PASSED = {
    "check_id": "EUGUARD_GDPR_001",
    "check_name": "Ensure resources stay in EU regions",
    "resource": "aws_s3_bucket.eu_ok",
    "file_path": "/main.tf",
    "file_line_range": [1, 3],
}


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
