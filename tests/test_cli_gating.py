"""CLI severity-gate and exit-status tests."""

import json

import pytest
from cli_helpers import FIXTURE, run_cli

from tf_eu_guard.cli import main
from tf_eu_guard.constants import (
    EXIT_FINDINGS,
    EXIT_OK,
)


def test_fail_on_severity_empty_disables_gating(monkeypatch, tmp_path, repo_root):
    """An empty severity value disables the gate."""
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--fail-on-severity",
        "",
    )
    assert rc == 0


def test_fail_on_severity_invalid_value_exits(monkeypatch, tmp_path, repo_root):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tf-eu-guard",
            "scan",
            "--checkov-json",
            str(repo_root / FIXTURE),
            "--output",
            "json",
            "--fail-on-severity",
            "BOGUS",
        ],
    )
    with pytest.raises(SystemExit):
        main()


def test_fail_on_severity_high_gates_on_findings(monkeypatch, tmp_path, repo_root):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--fail-on-severity",
        "HIGH",
    )
    assert rc == EXIT_FINDINGS


@pytest.mark.parametrize("threshold", ["CRITICAL", "HIGH", "MEDIUM"])
def test_fail_on_severity_triggers(monkeypatch, tmp_path, repo_root, threshold):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--fail-on-severity",
        threshold,
    )
    assert rc == EXIT_FINDINGS


def test_fail_on_severity_high_excludes_medium(monkeypatch, tmp_path):
    """A MEDIUM finding fails MEDIUM but passes HIGH."""
    document = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_40",
                    "check_name": "check",
                    "resource": "aws_x.y",
                    "file_path": "/a.tf",
                    "file_line_range": [1, 2],
                    "guideline": None,
                }
            ]
        }
    }
    finding_file = tmp_path / "medium.json"
    finding_file.write_text(json.dumps(document))

    assert (
        run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            str(finding_file),
            "--output",
            "json",
            "--fail-on-severity",
            "HIGH",
        )
        == EXIT_OK
    )
    assert (
        run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            str(finding_file),
            "--output",
            "json",
            "--fail-on-severity",
            "MEDIUM",
        )
        == EXIT_FINDINGS
    )


def test_fail_on_any(monkeypatch, tmp_path, repo_root):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--fail-on-any",
    )
    assert rc == EXIT_FINDINGS


def test_no_gate_by_default(monkeypatch, tmp_path, repo_root):
    """No gating flags preserve the default successful exit."""
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
    )
    assert rc == EXIT_OK


def test_fail_on_severity_empty_findings(monkeypatch, tmp_path):
    document = {"results": {"failed_checks": []}}
    finding_file = tmp_path / "empty.json"
    finding_file.write_text(json.dumps(document))
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(finding_file),
        "--output",
        "json",
        "--fail-on-severity",
        "LOW",
    )
    assert rc == EXIT_OK
