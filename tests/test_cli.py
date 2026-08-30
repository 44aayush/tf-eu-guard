"""Tests for the CLI entry point (scan command, exit codes, report formats).

Uses ``--checkov-json`` with the committed fixture so no Checkov run (or
network) is needed — the tests exercise argparse wiring, framework filtering,
report generation and the severity-based exit codes end-to-end.
"""

import json

import pytest

from tf_eu_guard.cli import main

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"


def run_cli(monkeypatch, tmp_path, *argv):
    """Invoke main() with argv, chdir'd into tmp_path. Returns exit code."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", *argv])
    return main()


def test_version_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "version"])
    assert main() == 0
    assert "version" in capsys.readouterr().out


def test_scan_requires_path(monkeypatch):
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan"])
    with pytest.raises(SystemExit):
        main()  # argparse error exits with code 2


def test_scan_dev_output(monkeypatch, tmp_path, repo_root):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "dev")
    assert rc == 0


def test_scan_json_output(monkeypatch, tmp_path, repo_root, capsys):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "json")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and len(data) > 0
    assert all("check_id" in f and "articles" in f for f in data)


def test_scan_framework_filter_nis2(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
            "--output", "json", "--framework", "nis2")
    data = json.loads(capsys.readouterr().out)
    assert all(any(a["framework"] == "NIS2" for a in f["articles"]) for f in data)


def test_scan_framework_filter_gdpr(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
            "--output", "json", "--framework", "gdpr")
    data = json.loads(capsys.readouterr().out)
    assert all(any(a["framework"] == "GDPR" for a in f["articles"]) for f in data)


def test_scan_html_reports(monkeypatch, tmp_path, repo_root):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "all")
    assert rc == 0
    htmls = list(tmp_path.glob("reports/*.html"))
    assert len(htmls) == 3  # dev, security, auditor


def test_scan_invalid_framework_exits(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "x/", "--framework", "bogus"])
    with pytest.raises(SystemExit):
        main()  # argparse rejects invalid choice with code 2


def test_scan_missing_file(monkeypatch, tmp_path):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", "no-such.json")
    assert rc == 1
    # nonexistent directory without --checkov-json also fails gracefully
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "no-such-dir/"])
    assert main() == 1


# --- Severity-based exit codes (CI/CD gating) ---


@pytest.mark.parametrize("threshold,expected", [
    ("CRITICAL", 1),  # fixture contains CRITICAL findings
    ("HIGH", 1),
    ("MEDIUM", 1),
])
def test_fail_on_severity_triggers(monkeypatch, tmp_path, repo_root, threshold, expected):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "json", "--fail-on-severity", threshold)
    assert rc == expected


def test_fail_on_severity_high_excludes_medium(monkeypatch, tmp_path, registry):
    """A single MEDIUM-severity finding fails MEDIUM threshold but passes HIGH."""
    doc = {
        "results": {"failed_checks": [{
            "check_id": "CKV_AWS_40",  # registry severity: MEDIUM
            "check_name": "check",
            "resource": "aws_x.y",
            "file_path": "/a.tf",
            "file_line_range": [1, 2],
            "guideline": None,
        }]}
    }
    med_file = tmp_path / "med.json"
    med_file.write_text(json.dumps(doc))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(med_file),
                 "--output", "json", "--fail-on-severity", "HIGH")
    assert rc == 0
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(med_file),
                 "--output", "json", "--fail-on-severity", "MEDIUM")
    assert rc == 1


def test_fail_on_any(monkeypatch, tmp_path, repo_root):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "json", "--fail-on-any")
    assert rc == 1


def test_no_gate_by_default(monkeypatch, tmp_path, repo_root):
    """Backward compatibility: no gating flags -> exit 0 despite findings."""
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE),
                 "--output", "json")
    assert rc == 0


def test_fail_on_severity_empty_findings(monkeypatch, tmp_path):
    doc = {"results": {"failed_checks": []}}
    f = tmp_path / "empty.json"
    f.write_text(json.dumps(doc))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f),
                 "--output", "json", "--fail-on-severity", "LOW")
    assert rc == 0
