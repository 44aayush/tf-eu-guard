"""Tests for the subcommand dispatcher and ``explain``."""

from pathlib import Path

from cli_helpers import FIXTURE, run_cli, run_command

from tf_eu_guard.cli import main


def test_explain_prints_registry_entry(monkeypatch, tmp_path, capsys):
    assert run_command(monkeypatch, tmp_path, "explain", "CKV_AWS_16") == 0
    out = capsys.readouterr().out
    assert "CKV_AWS_16" in out and "Severity:" in out and "Art. 32(1)(a)" in out
    assert "Remediation:" in out


def test_explain_is_case_insensitive(monkeypatch, tmp_path):
    assert run_command(monkeypatch, tmp_path, "explain", "ckv_aws_16") == 0


def test_explain_unknown_check_exits_2(monkeypatch, tmp_path, capsys):
    assert run_command(monkeypatch, tmp_path, "explain", "CKV_NOPE_1") == 2
    assert "not in the registry" in capsys.readouterr().err


def test_explain_without_id_exits_2(monkeypatch, tmp_path):
    assert run_command(monkeypatch, tmp_path, "explain") == 2


def test_scan_still_parses_after_dispatcher(monkeypatch, tmp_path):
    fixture = Path(__file__).parent.parent / FIXTURE
    assert run_cli(monkeypatch, tmp_path, "--checkov-json", str(fixture)) == 0


def test_explain_registry_load_failure_exits_3(monkeypatch, tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "explain", "CKV_AWS_16"])
    assert main(registry_path=empty) == 3
    assert "Error" in capsys.readouterr().err
