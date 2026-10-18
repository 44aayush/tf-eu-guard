"""CLI invalid-input and scanner-error tests."""

import json
import subprocess
from pathlib import Path

import pytest
from cli_helpers import FIXTURE, run_cli

from tf_eu_guard.cli import _exit_code_for, main
from tf_eu_guard.constants import (
    EXIT_FINDINGS,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_RUNTIME_FAILURE,
)
from tf_eu_guard.mapping.loader import RegistryValidationError


def test_scan_checkov_json_rejects_raw_plan_json(monkeypatch, tmp_path, repo_root, capsys):
    """A raw Terraform plan is not accepted as pre-generated Checkov output."""
    plan = repo_root / "examples/vulnerable-aws-plan/plan.json"
    if not plan.exists():
        pytest.skip("examples/vulnerable-aws-plan/plan.json not present")
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(plan),
        "--iac-type",
        "terraform_plan",
        "--output",
        "json",
    )
    assert rc == EXIT_INVALID_INPUT
    assert "does not look like Checkov output" in capsys.readouterr().err


def test_scan_missing_file(monkeypatch, tmp_path, capsys):
    """Missing scan inputs are invalid invocation errors."""
    assert run_cli(monkeypatch, tmp_path, "--checkov-json", "no-such.json") == 2
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "no-such-dir/"])
    assert main() == EXIT_INVALID_INPUT
    assert "invalid input/configuration" in capsys.readouterr().err


def test_exit_code_for_maps_exceptions():
    """User input errors and tool failures have distinct exit codes."""
    assert EXIT_OK == 0 and EXIT_FINDINGS == 1
    assert EXIT_INVALID_INPUT == 2 and EXIT_RUNTIME_FAILURE == 3
    assert _exit_code_for(ValueError("bad iac_type")) == EXIT_INVALID_INPUT
    assert _exit_code_for(json.JSONDecodeError("malformed", "{}", 0)) == EXIT_INVALID_INPUT
    assert _exit_code_for(FileNotFoundError("no such file")) == EXIT_INVALID_INPUT
    assert _exit_code_for(RegistryValidationError("schema violation")) == EXIT_RUNTIME_FAILURE
    assert _exit_code_for(
        subprocess.CalledProcessError(2, "checkov")
    ) == EXIT_RUNTIME_FAILURE
    assert _exit_code_for(RuntimeError("unexpected")) == EXIT_RUNTIME_FAILURE


@pytest.mark.parametrize(
    ("registry_text", "expected_error"),
    [
        ("CKV_AWS_1:\n  check_name: x\n", "missing required field"),
        ("? [a, b]\n: value\n", "non-string mapping key"),
    ],
    ids=["schema-error", "unhashable-key"],
)
def test_malformed_registry_exits_3(
    monkeypatch, tmp_path, capsys, registry_text, expected_error
):
    """A malformed packaged registry is a runtime failure."""
    fake_package = tmp_path / "fake_pkg"
    mapping_dir = fake_package / "mapping"
    mapping_dir.mkdir(parents=True)
    (mapping_dir / "registry-broken.yaml").write_text(registry_text)
    monkeypatch.setattr("tf_eu_guard.cli.__file__", str(fake_package / "cli.py"))

    source = tmp_path / "empty.json"
    source.write_text(json.dumps({"results": {"failed_checks": []}}))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(source), "--output", "json")
    assert rc == EXIT_RUNTIME_FAILURE
    error = capsys.readouterr().err
    assert "scanner/runtime failure" in error
    assert expected_error in error


def test_checkov_crash_exits_3(monkeypatch, tmp_path, capsys):
    """A Checkov process failure is a runtime failure."""
    def fake_run_checkov(target, iac_type="terraform"):
        raise subprocess.CalledProcessError(2, ["checkov"])

    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", fake_run_checkov)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan"])
    assert main() == EXIT_RUNTIME_FAILURE
    assert "scanner/runtime failure" in capsys.readouterr().err


def test_malformed_checkov_json_exits_2(monkeypatch, tmp_path):
    finding_file = tmp_path / "garbage.json"
    finding_file.write_text("{not json")
    assert run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(finding_file),
        "--output",
        "json",
    ) == EXIT_INVALID_INPUT


def test_checkov_json_directory_exits_2(monkeypatch, tmp_path, capsys):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(tmp_path), "--output", "json")
    captured = capsys.readouterr()
    assert rc == EXIT_INVALID_INPUT
    assert captured.out == ""
    assert "invalid input/configuration" in captured.err


def test_checkov_json_permission_error_exits_2(monkeypatch, tmp_path, capsys):
    finding_file = tmp_path / "permission.json"
    finding_file.write_text("{}")
    original_read_text = Path.read_text

    def denied(path, *args, **kwargs):
        if path == finding_file:
            raise PermissionError(13, "Permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(finding_file),
        "--output",
        "json",
    )
    assert rc == EXIT_INVALID_INPUT
    assert "Cannot read Checkov JSON input" in capsys.readouterr().err


def test_malformed_checkov_shape_exits_2(monkeypatch, tmp_path):
    finding_file = tmp_path / "wrong-shape.json"
    finding_file.write_text(json.dumps({"results": {"failed_checks": "not-a-list"}}))
    assert run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(finding_file),
        "--output",
        "json",
    ) == EXIT_INVALID_INPUT


@pytest.mark.parametrize(
    "field_value",
    [
        {"check_id": None},
        {"check_id": ""},
        {"resource": ["not", "a", "string"]},
        {"file_path": None},
        {"file_line_range": ["1", "2"]},
    ],
)
def test_malformed_checkov_finding_exits_2_without_null_sarif_id(
    monkeypatch, tmp_path, capsys, field_value
):
    check = {
        "check_id": "CKV_AWS_18",
        "check_name": "check",
        "resource": "aws_x.y",
        "file_path": "/main.tf",
        "file_line_range": [1, 2],
    }
    check.update(field_value)
    source = tmp_path / "malformed.json"
    source.write_text(json.dumps({"results": {"failed_checks": [check]}}))
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(source),
        "--output",
        "sarif",
    )
    assert rc == EXIT_INVALID_INPUT
    assert "invalid input/configuration" in capsys.readouterr().err


def test_malformed_checkov_fixture_exits_2(monkeypatch, tmp_path, repo_root, capsys):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / "tests/fixtures/malformed-checkov.json"),
        "--output",
        "sarif",
    )
    captured = capsys.readouterr()
    assert rc == EXIT_INVALID_INPUT
    assert captured.out == ""
    assert "check_id must be a non-empty string" in captured.err


def test_symlink_outside_scan_root_exits_2(monkeypatch, tmp_path, repo_root, capsys):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / "tests/fixtures/symlink-outside"),
        "--output",
        "json",
    )
    assert rc == EXIT_INVALID_INPUT
    assert "resolves outside scan root" in capsys.readouterr().err


def test_malformed_registry_injected_into_cli_exits_3(
    monkeypatch, tmp_path, capsys, repo_root
):
    empty_registry = tmp_path / "empty-mapping"
    empty_registry.mkdir()
    source = repo_root / FIXTURE
    monkeypatch.chdir(tmp_path)
    arguments = ["tf-eu-guard", "scan", "--checkov-json", str(source), "--output", "json"]
    monkeypatch.setattr("sys.argv", arguments)
    assert main(registry_path=empty_registry) == EXIT_RUNTIME_FAILURE
    assert "scanner/runtime failure" in capsys.readouterr().err

    monkeypatch.setattr("sys.argv", arguments)
    assert main(registry_path=tmp_path / "missing-mapping") == EXIT_RUNTIME_FAILURE
    assert "registry path does not exist" in capsys.readouterr().err
