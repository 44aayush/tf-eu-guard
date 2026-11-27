"""CLI severity-gate and exit-status tests."""

import argparse
import json

import pytest
from cli_helpers import FIXTURE, run_cli

from tf_eu_guard.cli import main
from tf_eu_guard.cli.gating import apply_scan_gate
from tf_eu_guard.cli.parser import build_parser
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
    document["summary"] = {"resource_count": 1, "parsing_errors": 0}
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
    document["summary"] = {"resource_count": 1, "parsing_errors": 0}
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


def _gate_args(**overrides):
    values = {
        "fail_on_severity": None,
        "fail_on_any": False,
        "fail_on_suppressed": False,
        "fail_on_unmapped": False,
        "unmapped_severity": None,
    }
    return argparse.Namespace(**{**values, **overrides})


_UNMAPPED = [{"check_id": "CKV_X_1"}]


def test_unmapped_severity_counts_at_threshold(capsys):
    args = _gate_args(fail_on_severity="HIGH", unmapped_severity="HIGH")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert (
        "Fail: 1 unmapped Checkov finding(s) counted as HIGH (--unmapped-severity) "
        "at or above threshold (HIGH)." in err
    )


def test_unmapped_severity_below_threshold_passes(capsys):
    args = _gate_args(fail_on_severity="HIGH", unmapped_severity="MEDIUM")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_OK
    err = capsys.readouterr().err
    assert "Note: 1 unmapped Checkov finding(s)" in err
    assert "Fail:" not in err


def test_unmapped_severity_with_fail_on_any(capsys):
    args = _gate_args(fail_on_any=True, unmapped_severity="INFO")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_FINDINGS
    assert "threshold (ANY)" in capsys.readouterr().err


def test_unmapped_severity_without_gate_is_inert(capsys):
    args = _gate_args(unmapped_severity="CRITICAL")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_OK
    err = capsys.readouterr().err
    assert "Fail:" not in err
    assert "Note:" not in err


def test_unmapped_severity_counted_suppresses_note(capsys):
    args = _gate_args(fail_on_severity="HIGH", unmapped_severity="MEDIUM", fail_on_unmapped=True)
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_FINDINGS
    assert "Note:" not in capsys.readouterr().err


def test_unmapped_severity_empty_disables():
    parser = build_parser()
    assert parser.parse_args(["scan", "--unmapped-severity", ""]).unmapped_severity is None
    assert parser.parse_args(["scan", "--unmapped-severity", "high"]).unmapped_severity == "HIGH"
    assert parser.parse_args(["scan"]).unmapped_severity is None


def _unmapped_doc(section):
    check = {
        "check_id": "CKV_ZZZ_999",
        "check_name": "unmapped",
        "resource": "aws_x.y",
        "file_path": "/a.tf",
        "file_line_range": [1, 2],
    }
    euguard = dict(check, check_id="EUGUARD_GDPR_001", resource="aws_s3_bucket.x")
    results = {"passed_checks": [euguard], "failed_checks": [], "skipped_checks": []}
    results[section] = [check]
    return {
        "check_type": "terraform",
        "results": results,
        "summary": {"parsing_errors": 0, "resource_count": 1},
    }


@pytest.mark.parametrize(("section", "expected"), [("skipped_checks", 0), ("failed_checks", 1)])
def test_unmapped_severity_ignores_suppressed(monkeypatch, tmp_path, section, expected):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(_unmapped_doc(section)), encoding="utf-8")
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--fail-on-any",
        "--unmapped-severity",
        "CRITICAL",
        "--no-config",
    )
    assert rc == expected
