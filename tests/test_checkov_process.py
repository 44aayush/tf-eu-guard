"""Validate the Checkov runner (tf_eu_guard.checkov_runner).

``extract_failed_checks`` is tested hermetically against a sample payload. The
live ``run_checkov`` smoke test is opt-in (set ``TFEG_RUN_CHECKOV=1`` and have
the ``checkov`` CLI installed) so the default ``pytest`` run stays fast; the
consolidated ``tests/run_all_tests.sh`` enables it automatically when Checkov
is present.
"""

import importlib.util
import json
import os
import sys

import pytest

from tf_eu_guard.checkov_runner import (
    CheckovRuntimeError,
    extract_failed_checks,
    run_checkov,
)
from tf_eu_guard.constants import SUPPORTED_IAC_TYPES

SAMPLE = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_17",
                "check_name": "Ensure all data stored in RDS is not publicly accessible",
                "resource": "aws_db_instance.default",
                "file_path": "/rds.tf",
                "file_line_range": [1, 20],
                "guideline": "https://docs.example/CKV_AWS_17",
            },
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                "resource": "aws_s3_bucket_acl.data",
                "file_path": "/s3.tf",
                "file_line_range": [5, 9],
                "guideline": None,
            },
        ]
    },
    "summary": {"parsing_errors": 0},
}


@pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or importlib.util.find_spec("checkov") is None,
    reason="live Checkov smoke test: set TFEG_RUN_CHECKOV=1 with Checkov installed in this Python environment",
)
def test_run_checkov_live_smoke(vulnerable_stack_dir):
    if not vulnerable_stack_dir.exists():
        pytest.skip("examples/vulnerable-aws/ not present")
    data = run_checkov(vulnerable_stack_dir)
    assert "results" in data
    findings = extract_failed_checks(data)
    assert findings, "expected the vulnerable stack to produce failed checks"
    assert all(f["check_id"] for f in findings)


@pytest.mark.parametrize("returncode", [1, 2])
def test_run_checkov_invalid_json_is_runtime_failure(tmp_path, returncode):
    def fake_run(cmd, **kwargs):
        return type(
            "R", (), {
                "returncode": returncode,
                "stdout": "",
                "stderr": "traceback line\nfinal Checkov crash detail",
            }
        )()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match="final Checkov crash detail"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_nonzero_status_includes_stderr(tmp_path):
    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 2,
            "stdout": "{}",
            "stderr": "configuration error: bad fixture",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match="configuration error: bad fixture"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_parsing_errors_and_names_files(tmp_path):
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [],
            "parsing_errors": ["broken.tf"],
        },
        "summary": {"parsing_errors": 1},
    }

    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match=r"parsing error.*broken\.tf"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_summary_only_empty_source_scan(tmp_path):
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
    }

    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        with pytest.raises(CheckovRuntimeError, match="no terraform scan results"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_tf_json_source(tmp_path):
    (tmp_path / "main.tf.json").write_text("{}\n")
    with pytest.raises(ValueError, match=r"\.tf\.json"):
        run_checkov(tmp_path)


def test_run_checkov_rejects_symlink_outside_scan_root(repo_root):
    target = repo_root / "tests" / "fixtures" / "symlink-outside"

    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(target)


def test_run_checkov_rejects_symlink_directory_outside_scan_root(repo_root):
    target = repo_root / "tests" / "fixtures" / "symlink-outside-dir"

    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(target)


def test_run_checkov_allows_in_root_symlinks(repo_root, monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    target = repo_root / "tests" / "fixtures" / "symlink-in-root"

    output = run_checkov(target)

    assert output["results"]["failed_checks"]
    assert captured["cmd"][captured["cmd"].index("-d") + 1] == str(target.resolve())


def test_run_checkov_rejects_unknown_iac_type(tmp_path):
    with pytest.raises(ValueError, match="Unsupported iac_type"):
        run_checkov(tmp_path, "bogus_framework")


def test_run_checkov_rejects_missing_target(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_checkov(tmp_path / "no-such-dir")


def test_run_checkov_plan_requires_file(tmp_path):
    """terraform_plan scans a plan FILE — a directory is a target mismatch."""
    with pytest.raises(ValueError, match="terraform_plan requires a plan file"):
        run_checkov(tmp_path, "terraform_plan")


def test_run_checkov_plan_builds_file_invocation(repo_root):
    """Plan mode must invoke checkov -f <plan.json> --framework terraform_plan."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        plan_output = {**SAMPLE, "check_type": "terraform_plan"}
        return type("R", (), {"returncode": 0, "stdout": json.dumps(plan_output), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        plan = repo_root / "examples" / "vulnerable-aws-plan" / "plan.json"
        if not plan.exists():
            pytest.skip("examples/vulnerable-aws-plan/plan.json not present")
        out = run_checkov(plan, "terraform_plan")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[cmd.index("-f") + 1] == str(plan)
    assert cmd[cmd.index("--framework") + 1] == "terraform_plan"
    assert "-d" not in cmd
    assert extract_failed_checks(out)[0]["check_id"] == "CKV_AWS_17"


def test_run_checkov_directory_uses_dash_d(tmp_path):
    """Non-plan scans keep the -d <directory> invocation."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        out = run_checkov(tmp_path, "terraform")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[cmd.index("-d") + 1] == str(tmp_path)
    assert "-f" not in cmd
    assert extract_failed_checks(out)[0]["check_id"] == "CKV_AWS_17"


def test_run_checkov_invokes_own_interpreter(tmp_path):
    """Checkov runs in isolated mode through this process's interpreter."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        run_checkov(tmp_path, "terraform")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[0] == sys.executable
    assert cmd[1] == "-I"
    assert cmd[2] == "-c"
    assert "checkov.main" in cmd[3]


def test_run_checkov_does_not_forward_checkov_skip_environment(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch.setenv("CKV_SKIP_CHECK", "CKV_AWS_18")
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')

    run_checkov(tmp_path, "terraform")

    assert captured["env"]["PATH"]
    assert "CKV_SKIP_CHECK" not in captured["env"]
    assert captured["cwd"] != tmp_path


@pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="Checkov is not installed",
)
def test_run_checkov_checkout_cannot_shadow_checkov(tmp_path):
    """A package under the scanned directory is not importable by Checkov."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    sentinel = tmp_path / "shadowed"
    fake_checkov = target / "checkov"
    fake_checkov.mkdir()
    (fake_checkov / "__init__.py").write_text("")
    (fake_checkov / "main.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('shadowed')\n"
    )

    output = run_checkov(target)
    assert output["check_type"] == "terraform"
    assert not sentinel.exists()


@pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="Checkov is not installed",
)
def test_run_checkov_ignores_checkout_checkov_config(tmp_path):
    """A checkout .checkov.yml cannot suppress wrapper-required checks."""
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    (tmp_path / ".checkov.yml").write_text("skip-check: CKV_AWS_18\n")

    output = run_checkov(tmp_path)
    assert any(check["check_id"] == "CKV_AWS_18" for check in output["results"]["failed_checks"])


def test_supported_iac_types_contents():
    assert SUPPORTED_IAC_TYPES == (
        "terraform", "terraform_plan", "kubernetes",
    )
