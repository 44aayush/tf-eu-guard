"""--checkov-json input guards (T-08) and JSON report formats (T-14)."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.cli_helpers import FIXTURE, run_cli
from tf_eu_guard import REPORT_SCHEMA_PATH
from tf_eu_guard.checkov.json import CUSTOM_CHECKS_DIR, installed_checkov_version
from tf_eu_guard.constants import EXIT_OK, EXIT_RUNTIME_FAILURE

SKIPPED_FIXTURE = "tests/fixtures/checkov-skipped-tf.json"
UNMAPPED_FIXTURE = "tests/fixtures/checkov-unmapped-tf.json"
ABS_FIXTURE = str(Path(FIXTURE).resolve())
ABS_SKIPPED = str(Path(SKIPPED_FIXTURE).resolve())
ABS_UNMAPPED = str(Path(UNMAPPED_FIXTURE).resolve())
SCHEMA = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
EUGUARD_CHECK = {
    "check_id": "EUGUARD_GDPR_001",
    "check_name": "Ensure resources stay in EU regions",
    "resource": "aws_s3_bucket.x",
    "file_path": "/m.tf",
    "file_line_range": [1, 2],
}


def _doc(*, parsing_errors=0, version=None, euguard=True, failed=None, skipped=None):
    summary: dict = {"parsing_errors": parsing_errors}
    if version:
        summary["checkov_version"] = version
    results = {
        "passed_checks": [],
        "failed_checks": failed or [],
        "skipped_checks": skipped or [],
    }
    if euguard:
        results["passed_checks"].append(EUGUARD_CHECK)
    return {"check_type": "terraform", "results": results, "summary": summary}


def _write(tmp_path: Path, data) -> str:
    path = tmp_path / "in.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _scan(monkeypatch, tmp_path, data, *extra):
    return run_cli(monkeypatch, tmp_path, "--checkov-json", _write(tmp_path, data), *extra)


def test_parsing_errors_fail_closed_with_fail_on_any(monkeypatch, tmp_path, capsys):
    """TASKS.md T-08 evidence: 2 parsing errors, 7 skipped, checkov 2.0.0."""
    skipped = [dict(EUGUARD_CHECK, resource=f"r.{i}") for i in range(7)]
    data = _doc(parsing_errors=2, version="2.0.0", skipped=skipped)
    code = _scan(monkeypatch, tmp_path, data, "--fail-on-any")
    err = capsys.readouterr().err
    assert code == EXIT_RUNTIME_FAILURE
    assert "2 parsing error(s)" in err
    assert "--allow-partial" in err


def test_version_mismatch_warning_names_both_versions(monkeypatch, tmp_path, capsys):
    code = _scan(monkeypatch, tmp_path, _doc(version="2.0.0"))
    err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "Checkov 2.0.0" in err
    assert f"Checkov {installed_checkov_version()} is installed" in err


def test_matching_version_has_no_version_warning(monkeypatch, tmp_path, capsys):
    _scan(monkeypatch, tmp_path, _doc(version=installed_checkov_version()))
    assert "was produced by Checkov" not in capsys.readouterr().err


def test_missing_version_has_no_version_warning(monkeypatch, tmp_path, capsys):
    _scan(monkeypatch, tmp_path, _doc())
    assert "was produced by Checkov" not in capsys.readouterr().err


def test_missing_euguard_checks_warns_with_checks_path(monkeypatch, tmp_path, capsys):
    code = _scan(monkeypatch, tmp_path, _doc(euguard=False))
    err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "no EUGUARD_* result appears" in err
    assert f"--external-checks-dir {CUSTOM_CHECKS_DIR}" in err


@pytest.mark.parametrize("section", ["passed_checks", "failed_checks", "skipped_checks"])
def test_euguard_in_any_list_suppresses_warning(monkeypatch, tmp_path, capsys, section):
    data = _doc(euguard=False)
    data["results"][section].append(EUGUARD_CHECK)
    _scan(monkeypatch, tmp_path, data)
    assert "no EUGUARD_* result appears" not in capsys.readouterr().err


def test_allow_partial_downgrades_parsing_errors(monkeypatch, tmp_path, capsys):
    code = _scan(monkeypatch, tmp_path, _doc(parsing_errors=2), "--allow-partial")
    err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "2 parsing error(s)" in err
    assert "--allow-partial" in err


def test_parsing_errors_in_any_list_element_fail(monkeypatch, tmp_path, capsys):
    other = {
        "check_type": "kubernetes",
        "results": {"failed_checks": []},
        "summary": {"parsing_errors": 1},
    }
    code = _scan(monkeypatch, tmp_path, [_doc(), other])
    assert code == EXIT_RUNTIME_FAILURE
    assert "1 parsing error(s)" in capsys.readouterr().err


def test_results_parsing_errors_list_fails(monkeypatch, tmp_path, capsys):
    data = _doc()
    data["results"]["parsing_errors"] = ["/bad.tf"]
    code = _scan(monkeypatch, tmp_path, data)
    assert code == EXIT_RUNTIME_FAILURE
    assert "/bad.tf" in capsys.readouterr().err


def test_allow_partial_in_source_mode(monkeypatch, tmp_path, capsys):
    """validate_scan_output (source scans) honours --allow-partial too."""
    from tf_eu_guard.checkov.json import allow_partial_results, validate_scan_output
    from tf_eu_guard.checkov.types import CheckovRuntimeError

    data = _doc(parsing_errors=1)
    with pytest.raises(CheckovRuntimeError):
        validate_scan_output(data, "terraform")
    with allow_partial_results(True):
        assert validate_scan_output(data, "terraform") is data
    assert "1 parsing error(s)" in capsys.readouterr().err
    with pytest.raises(CheckovRuntimeError):  # flag does not leak
        validate_scan_output(data, "terraform")


def test_existing_fixture_still_scans(monkeypatch, tmp_path, capsys):
    code = run_cli(monkeypatch, tmp_path, "--checkov-json", ABS_FIXTURE)
    assert code == EXIT_OK
    assert "no EUGUARD_* result appears" in capsys.readouterr().err


# --- T-14 -------------------------------------------------------------------


def test_json_output_file_written_utf8(monkeypatch, tmp_path, capsys):
    out = tmp_path / "sub" / "out.json"
    code = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        ABS_FIXTURE,
        "--output",
        "json",
        "--output-file",
        str(out),
    )
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "JSON report written to" in captured.out
    assert not captured.out.lstrip().startswith("[")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data


def test_array_format_keys_unchanged(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", ABS_FIXTURE, "--output", "json")
    data = json.loads(capsys.readouterr().out)
    assert data
    for entry in data:
        assert set(entry) == {
            "check_id",
            "suppressed",
            "waived",
            "baselined",
            "suppression_reason",
            "severity",
            "resource",
            "file_path",
            "articles",
        }
        assert all(set(a) == {"framework", "article"} for a in entry["articles"])


def _object_report(monkeypatch, tmp_path, capsys, fixture, *extra):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        fixture,
        "--output",
        "json",
        "--json-format",
        "object",
        *extra,
    )
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("fixture", [ABS_FIXTURE, ABS_SKIPPED, ABS_UNMAPPED])
def test_object_format_validates_against_schema(monkeypatch, tmp_path, capsys, fixture):
    report = _object_report(monkeypatch, tmp_path, capsys, fixture)
    Draft202012Validator(SCHEMA).validate(report)
    assert report["schema_version"] == "2"
    assert report["tool"]["name"] == "tf-eu-guard"
    assert report["scan"]["iac_type"] == "terraform"
    assert report["scan"]["target"].startswith("checkov-json:")


def test_object_format_has_suppressed_and_unmapped(monkeypatch, tmp_path, capsys):
    report = _object_report(monkeypatch, tmp_path, capsys, ABS_SKIPPED)
    suppressed = [f for f in report["findings"] if f["suppressed"]]
    assert suppressed
    assert any(f["suppression_reason"] for f in suppressed)
    assert report["summary"]["suppressed"] >= len(suppressed)
    active = [f for f in report["findings"] if not f["suppressed"]]
    assert sum(report["summary"]["by_severity"].values()) == len(active)
    first = report["findings"][0]
    assert first["file_line_range"] and first["check_name"] and first["remediation"]
    assert all(a["title"] for f in report["findings"] for a in f["articles"])

    unmapped_report = _object_report(monkeypatch, tmp_path, capsys, ABS_UNMAPPED)
    assert unmapped_report["unmapped"]
    assert unmapped_report["summary"]["unmapped"] == len(unmapped_report["unmapped"])
    assert unmapped_report["checkov_version"] == "3.3.13"
    assert unmapped_report["summary"]["total"] == len(
        [f for f in unmapped_report["findings"] if not f["suppressed"]]
    ) + len([u for u in unmapped_report["unmapped"] if not u["suppressed"]])


def test_object_format_includes_suppressed_unmapped(monkeypatch, tmp_path, capsys):
    data = _doc(skipped=[dict(EUGUARD_CHECK, check_id="CKV_NOPE_1")])
    path = _write(tmp_path, data)
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", path, "--output", "json", "--json-format", "object"
    )
    report = json.loads(capsys.readouterr().out)
    Draft202012Validator(SCHEMA).validate(report)
    assert [u["suppressed"] for u in report["unmapped"]] == [True]
    assert report["summary"] == {
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "unmapped": 1,
        "suppressed": 1,
        "total": 0,
    }


def test_object_format_output_file(monkeypatch, tmp_path, capsys):
    out = tmp_path / "r.json"
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        ABS_FIXTURE,
        "--output",
        "json",
        "--json-format",
        "object",
        "--output-file",
        str(out),
    )
    Draft202012Validator(SCHEMA).validate(json.loads(out.read_text(encoding="utf-8")))


def test_schema_rejects_bad_documents():
    validator = Draft202012Validator(SCHEMA)
    assert list(validator.iter_errors([]))
    assert list(validator.iter_errors({"schema_version": "1"}))


# --- Strict input when a gate is set (T-10, TEG-09) ---------------------------------

#: The shape of the forged file from REVIEW.md E13: no checks at all, zero resources.
FORGED = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [],
        "passed_checks": [],
        "skipped_checks": [],
        "parsing_errors": [],
    },
    "summary": {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
        "checkov_version": "3.4.5",
    },
}
COMPLETE_FIXTURE = str(Path("tests/fixtures/checkov-gdpr001-alias.json").resolve())


def test_checkov_json_gate_without_custom_checks_only_warns(monkeypatch, tmp_path, capsys):
    data = _doc(euguard=False, version="3.4.5") | {
        "summary": {"parsing_errors": 0, "resource_count": 3}
    }
    code = _scan(monkeypatch, tmp_path, data, "--fail-on-severity", "LOW")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "no EUGUARD_* result appears" in err
    assert "cannot trust" not in err


def test_checkov_json_gate_real_non_aws_output_passes(monkeypatch, tmp_path, capsys):
    """Genuine Checkov output for Azure-only code has no EUGUARD_* entry (AWS-only checks)."""
    data = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AZURE_44",
                    "bc_check_id": "BC_AZR_STORAGE_2",
                    "check_name": "Ensure Storage Account is using the latest version of TLS "
                    "encryption",
                    "check_result": {"result": "FAILED", "evaluated_keys": ["min_tls_version"]},
                    "file_path": "/main.tf",
                    "file_line_range": [4, 10],
                    "resource": "azurerm_storage_account.sa",
                    "guideline": None,
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
        "summary": {
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 1,
            "checkov_version": "3.4.5",
        },
    }
    code = _scan(monkeypatch, tmp_path, data, "--fail-on-severity", "LOW")
    err = capsys.readouterr().err
    assert code != EXIT_RUNTIME_FAILURE
    assert "cannot trust" not in err
    assert "no EUGUARD_* result appears" in err


def test_checkov_json_gate_zero_resources_exits_3(monkeypatch, tmp_path, capsys):
    code = _scan(
        monkeypatch,
        tmp_path,
        _doc(version="3.4.5") | {"summary": {"parsing_errors": 0, "resource_count": 0}},
        "--fail-on-any",
    )
    assert code == EXIT_RUNTIME_FAILURE
    assert "reports 0 resources scanned" in capsys.readouterr().err


def test_checkov_json_gate_allow_partial_warns(monkeypatch, tmp_path, capsys):
    code = _scan(monkeypatch, tmp_path, FORGED, "--fail-on-severity", "LOW", "--allow-partial")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "no EUGUARD_* result appears" in err
    assert "Warning: the Checkov JSON reports 0 resources scanned" in err


def test_checkov_json_without_gate_only_warns(monkeypatch, tmp_path, capsys):
    code = _scan(monkeypatch, tmp_path, FORGED)
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "no EUGUARD_* result appears" in err
    assert "Warning: the Checkov JSON reports 0 resources scanned" in err


def test_checkov_json_gate_complete_input_passes(monkeypatch, tmp_path, capsys):
    code = run_cli(
        monkeypatch, tmp_path, "--checkov-json", COMPLETE_FIXTURE, "--fail-on-severity", "CRITICAL"
    )
    assert code in (EXIT_OK, 1)  # a finding may trip the gate; the input itself is accepted
    assert "cannot trust it" not in capsys.readouterr().err
