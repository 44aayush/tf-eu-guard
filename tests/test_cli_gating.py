"""CLI severity-gate and exit-status tests."""

import argparse
import json

import jsonschema
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
    assert "Note:" not in err


def test_gate_label_is_any_when_both_flags_set_unmapped(capsys):
    args = _gate_args(fail_on_any=True, fail_on_severity="HIGH", unmapped_severity="LOW")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "at or above threshold (ANY)." in err
    assert "threshold (HIGH)" not in err


def test_gate_label_is_any_when_both_flags_set_mapped(capsys):
    from types import SimpleNamespace

    from tf_eu_guard.models import Severity

    finding = SimpleNamespace(severity=Severity.LOW)
    args = _gate_args(fail_on_any=True, fail_on_severity="HIGH")
    assert apply_scan_gate(args, [finding], []) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "(ANY)" in err
    assert "(HIGH)" not in err


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


def test_fail_on_unmapped_with_unmapped_severity_suppresses_note(capsys):
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


def _unmapped_scan(monkeypatch, tmp_path, name, doc, *extra):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(path), "--no-config", "--output", "json",
        "--json-format", "object", "--output-file", str(tmp_path / name), *extra,
    )  # fmt: skip


_UNMAPPED_GATE = ("--fail-on-severity", "HIGH", "--unmapped-severity", "HIGH")


def test_unmapped_severity_with_baseline_only_new_fail(monkeypatch, tmp_path, capsys):
    doc = _unmapped_doc("failed_checks")
    assert _unmapped_scan(monkeypatch, tmp_path, "base.json", doc) == 0
    capsys.readouterr()
    base = str(tmp_path / "base.json")
    rc = _unmapped_scan(monkeypatch, tmp_path, "n.json", doc, "--baseline", base, *_UNMAPPED_GATE)
    assert rc == 0
    report = json.loads((tmp_path / "n.json").read_text())
    assert any(s.endswith("1 unmapped)") for s in report["scan"]["weakening_settings"])
    # the array format keeps stdout pure and prints the settings list on stderr
    rc = run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(tmp_path / "in.json"), "--no-config",
        "--output", "json", "--json-format", "array", "--baseline", base, *_UNMAPPED_GATE,
    )  # fmt: skip
    assert rc == 0
    assert "1 unmapped)" in capsys.readouterr().err
    doc["results"]["failed_checks"].append(
        dict(doc["results"]["failed_checks"][0], check_id="CKV_ZZZ_998")
    )
    rc = _unmapped_scan(monkeypatch, tmp_path, "n.json", doc, "--baseline", base, *_UNMAPPED_GATE)
    assert rc == EXIT_FINDINGS
    new = json.loads((tmp_path / "n.json").read_text())
    assert [u["check_id"] for u in new["unmapped"]] == ["CKV_ZZZ_998"]
    assert [u["check_id"] for u in new["baselined_unmapped"]] == ["CKV_ZZZ_999"]


def test_baselined_unmapped_in_json_object(monkeypatch, tmp_path):
    from tf_eu_guard import REPORT_SCHEMA_PATH

    doc = _unmapped_doc("failed_checks")
    _unmapped_scan(monkeypatch, tmp_path, "base.json", doc)
    base = str(tmp_path / "base.json")
    _unmapped_scan(monkeypatch, tmp_path, "n.json", doc, "--baseline", base)
    report = json.loads((tmp_path / "n.json").read_text())
    assert report["unmapped"] == []
    assert [u["check_id"] for u in report["baselined_unmapped"]] == ["CKV_ZZZ_999"]
    assert set(report["baselined_unmapped"][0]) == {
        "check_id", "check_name", "resource", "file_path", "file_line_range", "suppressed",
    }  # fmt: skip
    schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)


def test_baseline_chain_keeps_unmapped_known(monkeypatch, tmp_path):
    doc = _unmapped_doc("failed_checks")
    _unmapped_scan(monkeypatch, tmp_path, "base.json", doc)
    _unmapped_scan(
        monkeypatch, tmp_path, "gen2.json", doc, "--baseline", str(tmp_path / "base.json")
    )
    rc = _unmapped_scan(
        monkeypatch, tmp_path, "gen3.json", doc, "--baseline", str(tmp_path / "gen2.json"),
        *_UNMAPPED_GATE,
    )  # fmt: skip
    assert rc == 0
    report = json.loads((tmp_path / "gen3.json").read_text())
    assert report["unmapped"] == [] and len(report["baselined_unmapped"]) == 1


def test_one_fail_line_when_both_unmapped_gates_trip(capsys):
    args = _gate_args(fail_on_unmapped=True, fail_on_severity="HIGH", unmapped_severity="HIGH")
    assert apply_scan_gate(args, [], _UNMAPPED) == EXIT_FINDINGS
    fail_lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.startswith("Fail:")]
    assert len(fail_lines) == 1
    assert "(--fail-on-unmapped)" in fail_lines[0]
