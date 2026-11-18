"""CLI behavior for Checkov findings without registry mappings."""

import json

import pytest
from cli_helpers import run_cli

UNMAPPED_FIXTURE = "tests/fixtures/checkov-unmapped-tf.json"


def _mixed_doc():
    """Return one mapped and two unmapped Checkov failures."""
    return {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_40",
                    "check_name": "check",
                    "resource": "aws_x.y",
                    "file_path": "/a.tf",
                    "file_line_range": [1, 2],
                    "guideline": None,
                },
                {
                    "check_id": "CKV_AWS_10",
                    "check_name": "check",
                    "resource": "aws_iam_account_password_policy.weak",
                    "file_path": "/a.tf",
                    "file_line_range": [3, 4],
                    "guideline": None,
                },
                {
                    "check_id": "CKV_AWS_11",
                    "check_name": "check",
                    "resource": "aws_iam_account_password_policy.weak",
                    "file_path": "/a.tf",
                    "file_line_range": [3, 4],
                    "guideline": None,
                },
            ]
        }
    }


def test_unmapped_findings_not_in_json_stdout_but_counted_on_stderr(monkeypatch, tmp_path, capsys):
    """JSON remains a mapped-findings array while stderr reports unmapped data."""
    finding_file = tmp_path / "mixed.json"
    finding_file.write_text(json.dumps(_mixed_doc()))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(finding_file), "--output", "json")
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert [finding["check_id"] for finding in data] == ["CKV_AWS_40"]
    assert "2 unmapped Checkov finding(s)" in captured.err
    assert "no current EU regulatory mapping" in captured.err


def test_unmapped_only_scan_is_not_reported_clean(monkeypatch, tmp_path, capsys):
    """Mapped-zero plus unmapped findings must not use the clean banner."""
    document = _mixed_doc()
    document["results"]["failed_checks"] = document["results"]["failed_checks"][1:]
    finding_file = tmp_path / "unmapped-only.json"
    finding_file.write_text(json.dumps(document))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(finding_file), "--output", "dev")
    assert rc == 0
    output = capsys.readouterr().out
    assert "No compliance findings" not in output
    assert "2 unmapped" in output


def test_unmapped_findings_never_trip_the_gate(monkeypatch, tmp_path, capsys):
    """Gates consider mapped findings only."""
    document = _mixed_doc()
    document["results"]["failed_checks"] = document["results"]["failed_checks"][1:]
    finding_file = tmp_path / "unmapped-only.json"
    finding_file.write_text(json.dumps(document))
    for gate in (["--fail-on-any"], ["--fail-on-severity", "LOW"]):
        rc = run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            str(finding_file),
            "--output",
            "json",
            *gate,
        )
        assert rc == 0
        assert "do not affect this gate" in capsys.readouterr().err


def test_mapped_findings_still_trip_the_gate_alongside_unmapped(monkeypatch, tmp_path, capsys):
    """A mapped finding still fails when unmapped findings are present."""
    finding_file = tmp_path / "mixed.json"
    finding_file.write_text(json.dumps(_mixed_doc()))
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
    assert rc == 1
    assert "Fail: 1 finding(s)" in capsys.readouterr().err


def test_unmapped_count_in_all_html_reports(monkeypatch, tmp_path):
    finding_file = tmp_path / "mixed.json"
    finding_file.write_text(json.dumps(_mixed_doc()))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(finding_file), "--output", "all")
    assert rc == 0
    html_reports = {
        path.name.split("_")[0]: path.read_text() for path in tmp_path.glob("reports/*.html")
    }
    assert len(html_reports) == 3
    for report_kind, document in html_reports.items():
        assert "no current EU regulatory mapping" in document, f"{report_kind} report missing note"
    assert "Unmapped Checkov findings: 2" in html_reports["dev"]
    assert "Unmapped Checkov findings: 2" in html_reports["scan"]
    assert "<strong>2</strong> failed check(s)" in html_reports["auditor"]


def test_unmapped_fixture_regression(monkeypatch, tmp_path, repo_root, capsys):
    """Mapped findings enrich while the unmapped family remains visible on stderr."""
    fixture = repo_root / UNMAPPED_FIXTURE
    if not fixture.exists():
        pytest.skip(f"{UNMAPPED_FIXTURE} not present")
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(fixture), "--output", "json")
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert {finding["check_id"] for finding in data} >= {
        "CKV_AWS_9",
        "CKV_AWS_145",
        "CKV_AWS_18",
    }
    unmapped_family = {f"CKV_AWS_{number}" for number in range(10, 16)}
    assert not unmapped_family & {finding["check_id"] for finding in data}
    assert "6 unmapped Checkov finding(s)" in captured.err


def _write_mixed(tmp_path, skipped=False):
    document = _mixed_doc()
    if skipped:
        document["results"]["failed_checks"] = [
            {**check, "check_result": {"result": "SKIPPED"}}
            for check in document["results"]["failed_checks"][1:]
        ]
        document["results"]["skipped_checks"] = document["results"]["failed_checks"]
        document["results"]["failed_checks"] = []
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps(document))
    return path


def test_show_unmapped_lists_them_in_dev_output(monkeypatch, tmp_path, capsys):
    path = _write_mixed(tmp_path)
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(path), "--show-unmapped")
    out = capsys.readouterr().out
    assert rc == 0
    assert "CKV_AWS_10" in out and "CKV_AWS_11" in out


def test_without_show_unmapped_only_count(monkeypatch, tmp_path, capsys):
    path = _write_mixed(tmp_path)
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(path))
    out = capsys.readouterr().out
    assert "CKV_AWS_10" not in out
    assert "2 " in out and "nmapped" in out


@pytest.mark.parametrize("kind", ["security", "auditor"])
def test_show_unmapped_in_html(monkeypatch, tmp_path, kind):
    path = _write_mixed(tmp_path)
    out_file = tmp_path / "r.html"
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--output",
        kind,
        "--output-file",
        str(out_file),
        "--show-unmapped",
    )
    assert "CKV_AWS_10" in out_file.read_text()


def test_show_unmapped_in_dev_html(monkeypatch, tmp_path):
    """The dev HTML report is only written through ``--output all``."""
    path = _write_mixed(tmp_path)
    out_dir = tmp_path / "out"
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--output",
        "all",
        "--output-dir",
        str(out_dir),
        "--show-unmapped",
    )
    dev = next(out_dir.glob("dev_report_*.html"))
    assert "CKV_AWS_10" in dev.read_text()


def test_html_without_show_unmapped_omits_list(monkeypatch, tmp_path):
    path = _write_mixed(tmp_path)
    out_file = tmp_path / "r.html"
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--output",
        "security",
        "--output-file",
        str(out_file),
    )
    assert "CKV_AWS_10" not in out_file.read_text()


def test_fail_on_unmapped_trips_gate(monkeypatch, tmp_path, capsys):
    path = _write_mixed(tmp_path)
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(path), "--fail-on-unmapped")
    err = capsys.readouterr().err
    assert rc == 1
    assert "Fail: 2 unmapped Checkov finding(s) (--fail-on-unmapped)" in err
    assert "do not affect this gate" not in err


def test_fail_on_unmapped_ignores_suppressed_unmapped(monkeypatch, tmp_path):
    path = _write_mixed(tmp_path, skipped=True)
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(path), "--fail-on-unmapped")
    assert rc == 0


def test_show_unmapped_html_escapes_values(monkeypatch, tmp_path):
    document = _mixed_doc()
    document["results"]["failed_checks"][1]["check_name"] = "<script>alert(1)</script>"
    path = tmp_path / "x.json"
    path.write_text(json.dumps(document))
    out_file = tmp_path / "r.html"
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(path), "--output", "security",
        "--output-file", str(out_file), "--show-unmapped",
    )  # fmt: skip
    text = out_file.read_text()
    assert "<script>alert(1)" not in text and "&lt;script&gt;" in text
