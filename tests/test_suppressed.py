"""Tests for findings suppressed by inline Checkov skip comments (T-01).

Checkov moves ``#checkov:skip=ID:reason`` (Terraform) and ``checkov.io/skip``
(Kubernetes) results into ``results.skipped_checks``. They must stay visible in
every report and be distinguishable from active findings.
"""

import json
from pathlib import Path

import pytest
from cli_helpers import EUGUARD_PASSED

from tf_eu_guard.checkov.json import (
    extract_failed_checks,
    extract_skipped_checks,
    suppression_reason,
    validate_checkov_output,
)
from tf_eu_guard.cli import main
from tf_eu_guard.constants import EXIT_FINDINGS, EXIT_OK
from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity

FIXTURE = "tests/fixtures/checkov-skipped-tf.json"
NO_REASON = "no reason given"
REASON_18 = "access logging handled by the central log account"
REASON_13 = "legacy account, rotation handled by SSO"


def run_cli(monkeypatch, tmp_path, *argv):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", *argv])
    return main()


@pytest.fixture
def fixture_path(repo_root) -> str:
    return str(repo_root / FIXTURE)


@pytest.fixture
def skipped_only_path(repo_root, tmp_path) -> str:
    """The fixture with no active failures: only suppressed checks remain."""
    data = json.loads((repo_root / FIXTURE).read_text())
    data["results"]["failed_checks"] = []
    path = tmp_path / "only-skipped.json"
    path.write_text(json.dumps(data))
    return str(path)


# --- parsing and validation -------------------------------------------------


def test_extract_skipped_checks_carries_reason(repo_root):
    data = json.loads((repo_root / FIXTURE).read_text())
    skipped = extract_skipped_checks(data)
    assert [c["check_id"] for c in skipped] == [
        "CKV_AWS_18",
        "CKV_AWS_145",
        "CKV_AWS_13",
        "CKV_AWS_15",
    ]
    assert all(c["suppressed"] is True for c in skipped)
    reasons = {c["check_id"]: c["suppression_reason"] for c in skipped}
    assert reasons["CKV_AWS_18"] == REASON_18
    assert reasons["CKV_AWS_13"] == REASON_13
    # Checkov's "No comment provided" placeholder means no reason was given.
    assert reasons["CKV_AWS_145"] is None
    assert reasons["CKV_AWS_15"] is None
    # Failed checks are unaffected.
    assert [c["check_id"] for c in extract_failed_checks(data)] == ["CKV_AWS_24"]


@pytest.mark.parametrize(
    "check_result",
    [None, "SKIPPED", {}, {"suppress_comment": None}, {"suppress_comment": "  "}],
)
def test_suppression_reason_tolerates_missing_comment(check_result):
    assert suppression_reason({"check_result": check_result}) is None


def test_missing_skipped_checks_key_is_accepted():
    data = {"results": {"failed_checks": []}}
    validate_checkov_output(data)
    assert extract_skipped_checks(data) == []


@pytest.mark.parametrize(
    ("skipped", "message"),
    [
        ("nope", "'results.skipped_checks' must be a list"),
        (["x"], r"'results.skipped_checks\[0\]' must be an object"),
        ([{"check_id": "CKV_X_1"}], r"results.skipped_checks\[0\]'? missing required"),
        (
            [
                {
                    "check_id": "CKV_X_1",
                    "check_name": "n",
                    "resource": "r",
                    "file_path": "/a.tf",
                    "file_line_range": [5, 1],
                }
            ],
            "file_line_range",
        ),
    ],
)
def test_malformed_skipped_checks_are_rejected(skipped, message):
    data = {"results": {"failed_checks": [], "skipped_checks": skipped}}
    with pytest.raises(ValueError, match=message):
        validate_checkov_output(data)


# --- models -----------------------------------------------------------------


def _finding(**overrides) -> EnrichedFinding:
    values = {
        "check_id": "CKV_AWS_18",
        "check_name": "name",
        "resource": "aws_s3_bucket.a",
        "file_path": "/a.tf",
        "file_line_range": [1, 2],
        "guideline": None,
        "articles": [ArticleReference(Framework.NIS2, "Art. 21(2)(b)", "Incident handling")],
        "severity": Severity.HIGH,
    }
    values.update(overrides)
    return EnrichedFinding(**values)


def test_finding_suppression_defaults():
    active = _finding()
    skipped = _finding(suppressed=True, suppression_reason="why")
    assert active.suppressed is False and active.suppression_reason is None
    assert skipped.suppressed is True and skipped.suppression_reason == "why"


# --- CLI: reports -----------------------------------------------------------


def test_json_output_marks_suppressed(monkeypatch, tmp_path, capsys, fixture_path):
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", fixture_path, "--output", "json")
    assert rc == EXIT_OK
    captured = capsys.readouterr()
    entries = {e["check_id"]: e for e in json.loads(captured.out)}
    assert set(entries) == {"CKV_AWS_24", "CKV_AWS_18", "CKV_AWS_145"}
    assert entries["CKV_AWS_24"]["suppressed"] is False
    assert entries["CKV_AWS_24"]["suppression_reason"] is None
    assert entries["CKV_AWS_18"]["suppressed"] is True
    assert entries["CKV_AWS_18"]["suppression_reason"] == REASON_18
    assert entries["CKV_AWS_145"]["suppressed"] is True
    assert entries["CKV_AWS_145"]["suppression_reason"] is None
    # Unmapped suppressed checks are noted on stderr, like unmapped active ones.
    assert "2 unmapped Checkov finding(s) suppressed" in captured.err


def test_dev_report_lists_suppressed_section(monkeypatch, tmp_path, capsys, fixture_path):
    run_cli(monkeypatch, tmp_path, "--checkov-json", fixture_path)
    out = capsys.readouterr().out
    assert "Suppressed by inline comment (4)" in out
    for expected in ("CKV_AWS_18", "CKV_AWS_145", "CKV_AWS_13", "CKV_AWS_15"):
        assert expected in out
    assert "aws_s3_bucket.logs" in out
    assert "/storage.tf:3-8" in out
    assert REASON_18 in out
    assert REASON_13 in out
    assert NO_REASON in out
    # The summary counts only the active finding.
    assert "Total Findings: 1" in out


def test_dev_report_is_not_clean_when_only_suppressed(
    monkeypatch, tmp_path, capsys, skipped_only_path
):
    run_cli(monkeypatch, tmp_path, "--checkov-json", skipped_only_path)
    out = capsys.readouterr().out
    assert "No compliance findings" not in out
    assert "No active findings; 4 suppressed" in out
    assert REASON_18 in out


def test_dev_report_clean_message_kept_without_suppressions(monkeypatch, tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"results": {"failed_checks": []}}))
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(path))
    assert "No compliance findings" in capsys.readouterr().out


@pytest.mark.parametrize("output", ["security", "auditor", "dev-html"])
def test_html_reports_list_suppressed(monkeypatch, tmp_path, fixture_path, output):
    out_file = tmp_path / "report.html"
    if output == "dev-html":
        # The dev HTML report is produced by --output all.
        rc = run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            fixture_path,
            "--output",
            "all",
            "--output-dir",
            str(tmp_path / "out"),
        )
        html = next((tmp_path / "out").glob("dev_report_*.html")).read_text()
    else:
        rc = run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            fixture_path,
            "--output",
            output,
            "--output-file",
            str(out_file),
        )
        html = out_file.read_text()
    assert rc == EXIT_OK
    assert "Suppressed by inline comment (4)" in html
    for expected in ("CKV_AWS_18", "CKV_AWS_145", "CKV_AWS_13", "CKV_AWS_15"):
        assert expected in html
    assert "aws_s3_bucket.logs" in html
    assert "/storage.tf:3-8" in html
    assert REASON_18 in html
    assert NO_REASON in html


@pytest.mark.parametrize("output", ["security", "auditor"])
def test_html_reports_are_not_clean_when_only_suppressed(
    monkeypatch, tmp_path, skipped_only_path, output
):
    out_file = tmp_path / "report.html"
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        skipped_only_path,
        "--output",
        output,
        "--output-file",
        str(out_file),
    )
    html = out_file.read_text()
    assert "No compliance findings" not in html
    assert "suppressed" in html.lower()
    assert REASON_13 in html


def test_html_escapes_suppression_reason(monkeypatch, tmp_path, repo_root):
    data = json.loads((repo_root / FIXTURE).read_text())
    data["results"]["skipped_checks"][0]["check_result"]["suppress_comment"] = "<script>x</script>"
    path = tmp_path / "xss.json"
    path.write_text(json.dumps(data))
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
    html = out_file.read_text()
    assert "<script>x" not in html
    assert "&lt;script&gt;" in html


def test_sarif_marks_suppressed_results(monkeypatch, tmp_path, capsys, fixture_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).parent / "schemas" / "sarif-2.1.0.json").read_text())
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", fixture_path, "--output", "sarif")
    assert rc == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    jsonschema.validate(document, schema)
    results = {r["ruleId"]: r for r in document["runs"][0]["results"]}
    assert set(results) == {
        "CKV_AWS_24",
        "CKV_AWS_18",
        "CKV_AWS_145",
        "CKV_AWS_13",
        "CKV_AWS_15",
    }
    assert "suppressions" not in results["CKV_AWS_24"]
    assert results["CKV_AWS_18"]["suppressions"] == [
        {"kind": "inSource", "justification": REASON_18}
    ]
    assert results["CKV_AWS_13"]["suppressions"] == [
        {"kind": "inSource", "justification": REASON_13}
    ]
    # No stated reason: still suppressed, but no invented justification.
    assert results["CKV_AWS_145"]["suppressions"] == [{"kind": "inSource"}]
    assert results["CKV_AWS_15"]["suppressions"] == [{"kind": "inSource"}]


# --- CLI: gating and framework filter ---------------------------------------


@pytest.mark.parametrize("gate", [["--fail-on-any"], ["--fail-on-severity", "INFO"]])
def test_suppressed_findings_do_not_trip_severity_gates(
    monkeypatch, tmp_path, skipped_only_path, gate
):
    rc = run_cli(
        monkeypatch, tmp_path, "--checkov-json", skipped_only_path, "--output", "json", *gate
    )
    assert rc == EXIT_OK


def test_active_finding_still_trips_gate_with_suppressions(monkeypatch, tmp_path, fixture_path):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        fixture_path,
        "--output",
        "json",
        "--fail-on-any",
    )
    assert rc == EXIT_FINDINGS


def test_fail_on_suppressed_trips_on_mapped_suppression(
    monkeypatch, tmp_path, capsys, skipped_only_path
):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        skipped_only_path,
        "--output",
        "json",
        "--fail-on-suppressed",
    )
    assert rc == EXIT_FINDINGS
    assert "--fail-on-suppressed" in capsys.readouterr().err


def test_fail_on_suppressed_ignores_unmapped_suppression(monkeypatch, tmp_path, repo_root):
    data = json.loads((repo_root / FIXTURE).read_text())
    data["results"]["failed_checks"] = []
    data["results"]["skipped_checks"] = [
        c
        for c in data["results"]["skipped_checks"]
        if c["check_id"] in ("CKV_AWS_13", "CKV_AWS_15")
    ]
    path = tmp_path / "unmapped-only.json"
    path.write_text(json.dumps(data))
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(path),
        "--output",
        "json",
        "--fail-on-suppressed",
    )
    assert rc == EXIT_OK


def test_fail_on_suppressed_off_by_default_and_without_suppressions(
    monkeypatch, tmp_path, fixture_path
):
    assert (
        run_cli(monkeypatch, tmp_path, "--checkov-json", fixture_path, "--output", "json")
        == EXIT_OK
    )
    clean = tmp_path / "clean.json"
    clean.write_text(
        json.dumps({"results": {"passed_checks": [EUGUARD_PASSED], "failed_checks": []}})
    )
    assert (
        run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            str(clean),
            "--output",
            "json",
            "--fail-on-suppressed",
        )
        == EXIT_OK
    )


def test_framework_filter_applies_to_suppressed(monkeypatch, tmp_path, capsys, skipped_only_path):
    # CKV_AWS_18 maps to NIS2 only; CKV_AWS_145 maps to NIS2 and GDPR.
    def suppressed_ids(framework):
        run_cli(
            monkeypatch,
            tmp_path,
            "--checkov-json",
            skipped_only_path,
            "--output",
            "json",
            "--framework",
            framework,
        )
        entries = json.loads(capsys.readouterr().out)
        assert all(e["suppressed"] for e in entries)
        return {e["check_id"] for e in entries}, entries

    nis2_ids, _ = suppressed_ids("nis2")
    assert nis2_ids == {"CKV_AWS_18", "CKV_AWS_145"}
    gdpr_ids, gdpr_entries = suppressed_ids("gdpr")
    assert gdpr_ids == {"CKV_AWS_145"}
    assert all(a["framework"] == "GDPR" for e in gdpr_entries for a in e["articles"])


def test_fail_on_suppressed_honors_framework_filter(monkeypatch, tmp_path, repo_root):
    data = json.loads((repo_root / FIXTURE).read_text())
    data["results"]["failed_checks"] = []
    # Keep only the NIS2-only suppressed check.
    data["results"]["skipped_checks"] = [
        c for c in data["results"]["skipped_checks"] if c["check_id"] == "CKV_AWS_18"
    ]
    path = tmp_path / "nis2-only.json"
    path.write_text(json.dumps(data))
    args = ("--checkov-json", str(path), "--output", "json", "--fail-on-suppressed")
    assert run_cli(monkeypatch, tmp_path, *args, "--framework", "gdpr") == EXIT_OK
    assert run_cli(monkeypatch, tmp_path, *args, "--framework", "nis2") == EXIT_FINDINGS


# --- end to end with real Checkov -------------------------------------------


def test_real_checkov_inline_skip_is_reported_as_suppressed(monkeypatch, tmp_path, capsys):
    target = tmp_path / "tf"
    target.mkdir()
    (target / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        "  #checkov:skip=CKV_AWS_18:access logging handled centrally\n"
        '  bucket = "logs"\n'
        "}\n"
    )
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(target),
        "--output",
        "json",
        "--fail-on-severity",
        "INFO",
    )
    entries = {e["check_id"]: e for e in json.loads(capsys.readouterr().out)}
    assert entries["CKV_AWS_18"]["suppressed"] is True
    assert entries["CKV_AWS_18"]["suppression_reason"] == "access logging handled centrally"
    assert entries["CKV_AWS_18"]["resource"] == "aws_s3_bucket.logs"
    # Other, unsuppressed checks on the same resource remain active.
    assert any(not e["suppressed"] for e in entries.values())
    assert rc == EXIT_FINDINGS  # from the active findings, not the suppressed one

    rc = run_cli(monkeypatch, tmp_path, str(target), "--output", "json", "--fail-on-suppressed")
    assert rc == EXIT_FINDINGS
