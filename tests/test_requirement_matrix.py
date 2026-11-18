"""Passed-check extraction, the requirement evidence matrix and JSON schema v2."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.cli_helpers import run_cli
from tf_eu_guard import REPORT_SCHEMA_PATH
from tf_eu_guard.checkov.json import extract_passed_checks
from tf_eu_guard.cli.pipeline import default_registry_dir
from tf_eu_guard.mapping.coverage import evaluate_requirements
from tf_eu_guard.mapping.enrichment import split_findings
from tf_eu_guard.mapping.loader import load_registry
from tf_eu_guard.reporting.auditor_report import generate_auditor_report

CHECK = {
    "check_id": "CKV_AWS_16",
    "check_name": "RDS encrypted",
    "resource": "aws_db_instance.a",
    "file_path": "/m.tf",
    "file_line_range": [1, 2],
}
FIXTURE = str(Path("tests/fixtures/checkov-vulnerable-tf.json").resolve())


def _doc(passed=None, failed=None):
    results = {"failed_checks": failed or [], "skipped_checks": []}
    if passed is not None:
        results["passed_checks"] = passed
    return {"check_type": "terraform", "results": results, "summary": {"parsing_errors": 0}}


def _registry():
    return load_registry(default_registry_dir())


def test_extract_passed_checks_reads_section():
    entries = extract_passed_checks(_doc(passed=[CHECK]))
    assert [(e["check_id"], e["resource"]) for e in entries] == [
        ("CKV_AWS_16", "aws_db_instance.a")
    ]


def test_extract_passed_checks_missing_is_empty():
    assert extract_passed_checks(_doc()) == []


@pytest.mark.parametrize("bad", ["x", {"a": 1}, ["x"]])
def test_extract_passed_checks_rejects_malformed(bad):
    with pytest.raises(ValueError, match="passed_checks"):
        extract_passed_checks(_doc(passed=bad))


def test_evaluate_requirements_has_fifteen_rows():
    rows = evaluate_requirements(_registry(), [], [], [])
    assert len(rows) == 15 and all(r.ran == 0 for r in rows)


def test_evaluate_requirements_counts_pass_and_fail():
    registry = _registry()
    passed, _ = split_findings([CHECK], registry)
    failed, _ = split_findings([dict(CHECK, resource="aws_db_instance.b")], registry)
    rows = evaluate_requirements(registry, passed, failed, [])
    row = next(r for r in rows if r.requirement.article == "32(1)(a)")
    assert (row.ran, row.passed, row.failed, row.suppressed, row.waived) == (2, 1, 1, 0, 0)


def _object(monkeypatch, tmp_path, capsys, *extra):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        FIXTURE,
        "--output",
        "json",
        "--json-format",
        "object",
        *extra,
    )
    return json.loads(capsys.readouterr().out)


def test_json_object_v2_validates_and_has_requirements(monkeypatch, tmp_path, capsys):
    doc = _object(monkeypatch, tmp_path, capsys)
    assert doc["schema_version"] == "2"
    assert len(doc["requirements"]) == 15
    assert doc["registry"] == {"overlays": [], "overridden": []}
    assert doc["waived"] == []
    Draft202012Validator(json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(doc)


def test_json_object_lists_registry_overrides(monkeypatch, tmp_path, capsys):
    overlay = tmp_path / "ov"
    overlay.mkdir()
    (overlay / "extra.yaml").write_text(
        "CKV_AWS_16:\n  check_name: P\n  severity: LOW\n  risk: r\n  remediation: f\n"
        "  articles:\n    - {framework: POLICY, article: 'Policy 7', title: 'T'}\n",
        encoding="utf-8",
    )
    doc = _object(monkeypatch, tmp_path, capsys, "--registry-dir", str(overlay))
    assert doc["registry"]["overridden"] == ["CKV_AWS_16"]
    assert doc["registry"]["overlays"] == [str(overlay / "extra.yaml")]


def test_auditor_report_lists_every_requirement():
    rows = evaluate_requirements(_registry(), [], [], [])
    html = generate_auditor_report([], requirements=rows)
    assert "Requirement evidence" in html
    section = html.split("Requirement evidence", 1)[1].split("</table>", 1)[0]
    assert section.count("<tr>") == 16  # header + 15 rows
    assert section.count("No mapped check was evaluated") == 15


def test_auditor_report_keeps_absence_disclaimer():
    rows = evaluate_requirements(_registry(), [], [], [])
    assert "not evidence of compliance" in generate_auditor_report([], requirements=rows)


def _scan_doc(monkeypatch, tmp_path, capsys, *extra):
    doc = _doc(
        passed=[CHECK],
        failed=[dict(CHECK, resource="aws_db_instance.b")],
    )
    path = tmp_path / "in.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--output",
        "json",
        "--json-format",
        "object",
        *extra,
    )
    return json.loads(capsys.readouterr().out)


def test_cli_counts_passed_and_failed_end_to_end(monkeypatch, tmp_path, capsys):
    rows = _scan_doc(monkeypatch, tmp_path, capsys)["requirements"]
    row = next(r for r in rows if r["framework"] == "GDPR" and r["article"] == "32(1)(a)")
    assert (row["passed"], row["failed"], row["ran"]) == (1, 1, 2)


@pytest.mark.parametrize(
    ("framework", "expected"), [("all", None), ("nis2", "NIS2"), ("gdpr", "GDPR")]
)
def test_requirement_rows_follow_framework(monkeypatch, tmp_path, capsys, framework, expected):
    rows = _scan_doc(monkeypatch, tmp_path, capsys, "--framework", framework)["requirements"]
    if expected is None:
        assert len(rows) == 15
    else:
        assert rows and {r["framework"] for r in rows} == {expected}


def test_auditor_table_follows_framework(monkeypatch, tmp_path):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        FIXTURE,
        "--framework",
        "nis2",
        "--output",
        "auditor",
        "--output-file",
        str(tmp_path / "a.html"),
    )
    html = (tmp_path / "a.html").read_text(encoding="utf-8")
    section = html.split("Requirement evidence", 1)[1].split("</table>", 1)[0]
    assert "NIS2 Art." in section and "GDPR Art." not in section
