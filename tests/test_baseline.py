"""Finding identity, --baseline and the diff subcommand (N-05, N-16)."""

import json
import re

import jsonschema
import pytest
from cli_helpers import FIXTURE, run_cli, run_command

from tf_eu_guard.baseline import BaselineError, finding_key, load_baseline


def _entry(check_id="CKV_AWS_18", resource="aws_s3_bucket.logs", path="/s3.tf", **extra):
    return {"check_id": check_id, "resource": resource, "file_path": path, **extra}


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_finding_key_ignores_leading_slash_and_lines():
    assert (
        finding_key("A", "r", "/x/y.tf") == finding_key("A", "r", "x\\y.tf") == ("A", "r", "x/y.tf")
    )
    assert finding_key("A", None, None) == ("A", "", "")


def test_load_baseline_v1_object(tmp_path):
    p = _write(tmp_path, "b.json", {"schema_version": "1", "findings": [_entry()]})
    b = load_baseline(p)
    assert b.keys == {finding_key("CKV_AWS_18", "aws_s3_bucket.logs", "/s3.tf")}
    assert b.created is None


def test_load_baseline_v2_object_skips_suppressed_and_waived(tmp_path):
    doc = {
        "schema_version": "2",
        "scan": {"timestamp": "2026-05-01T10:00:00Z"},
        "findings": [_entry(), _entry("CKV_AWS_19", suppressed=True)],
        "waived": [_entry("CKV_AWS_20")],
        "baselined": [_entry("CKV_AWS_21")],
    }
    b = load_baseline(_write(tmp_path, "b.json", doc))
    assert {k[0] for k in b.keys} == {"CKV_AWS_18", "CKV_AWS_21"}
    assert b.created is not None and b.created.date().isoformat() == "2026-05-01"


def test_baseline_accepts_v2_report(tmp_path):
    doc = {
        "schema_version": "2",
        "findings": [_entry()],
        "waived": [],
        "baselined": [],
    }
    b = load_baseline(_write(tmp_path, "b.json", doc))
    assert b.keys == {finding_key("CKV_AWS_18", "aws_s3_bucket.logs", "/s3.tf")}


def test_baseline_accepts_v3_report(tmp_path):
    doc = {"schema_version": "3", "findings": [_entry()]}
    assert len(load_baseline(_write(tmp_path, "b.json", doc)).keys) == 1


def test_baseline_matches_unmapped_from_v2_report(tmp_path):
    doc = {
        "schema_version": "2",
        "findings": [],
        "unmapped": [
            {"check_id": "CKV_ZZZ_999", "resource": "aws_s3_bucket.a", "file_path": "/main.tf"}
        ],
    }
    b = load_baseline(_write(tmp_path, "b.json", doc))
    assert b.unmapped_keys == {("CKV_ZZZ_999", "aws_s3_bucket.a", "main.tf")}
    assert b.keys == frozenset()


def test_array_baseline_has_no_unmapped_keys(tmp_path):
    b = load_baseline(_write(tmp_path, "b.json", [_entry()]))
    assert b.unmapped_keys == frozenset()


def test_suppressed_unmapped_entries_not_known(tmp_path):
    doc = {
        "findings": [],
        "unmapped": [
            _entry("CKV_ZZZ_1", suppressed=True),
            _entry("CKV_ZZZ_2", suppressed=False),
        ],
        "baselined_unmapped": [_entry("CKV_ZZZ_3", suppressed=True)],
    }
    b = load_baseline(_write(tmp_path, "b.json", doc))
    assert {k[0] for k in b.unmapped_keys} == {"CKV_ZZZ_2"}


@pytest.mark.parametrize("key", ["unmapped", "baselined_unmapped"])
def test_load_baseline_rejects_bad_unmapped_shapes(tmp_path, key):
    for bad in (5, [{"resource": "r"}]):
        with pytest.raises(BaselineError):
            load_baseline(_write(tmp_path, "b.json", {"findings": [], key: bad}))


def test_load_baseline_legacy_array(tmp_path):
    b = load_baseline(_write(tmp_path, "b.json", [_entry(), _entry("X", waived=True)]))
    assert len(b.keys) == 1


@pytest.mark.parametrize(
    "doc",
    [
        {"foo": 1},
        3,
        [{"resource": "r"}],
        {"findings": [{"nope": 1}]},
        {"findings": "x"},
        {"findings": [], "scan": "x"},
        {"findings": [], "scan": [1]},
        {"findings": [], "baselined": 5},
    ],
)
def test_load_baseline_rejects_bad_shapes(tmp_path, doc):
    with pytest.raises(BaselineError):
        load_baseline(_write(tmp_path, "b.json", doc))


def test_load_baseline_rejects_bad_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(bad)
    bad.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(BaselineError):
        load_baseline(bad)
    with pytest.raises(BaselineError):
        load_baseline(tmp_path)  # a directory
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "missing.json")


def _object_scan(monkeypatch, tmp_path, out, *extra):
    return run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(_abs(FIXTURE)), "--output", "json",
        "--json-format", "object", "--output-file", str(out), *extra,
    )  # fmt: skip


def _abs(rel):
    from pathlib import Path

    return Path(__file__).parent.parent / rel


def test_baseline_excludes_known_findings_from_gate(monkeypatch, tmp_path, capsys):
    base = tmp_path / "base.json"
    assert _object_scan(monkeypatch, tmp_path, base) == 0
    rc = _object_scan(monkeypatch, tmp_path, tmp_path / "n.json", "--baseline", str(base),
                      "--fail-on-any")  # fmt: skip
    err = capsys.readouterr().err
    assert rc == 0
    assert re.search(
        r"\d+ finding\(s\) match the baseline from \d{4}-\d\d-\d\d \(\d+ days old\)", err
    )
    doc = json.loads((tmp_path / "n.json").read_text())
    assert doc["findings"] == [] and doc["baselined"]
    assert any(s.startswith("baseline: ") for s in doc["scan"]["weakening_settings"])
    schema = json.loads((_abs("tf_eu_guard/schemas/report.schema.json")).read_text())
    jsonschema.validate(doc, schema)


def test_new_finding_still_trips_gate_with_baseline(monkeypatch, tmp_path, capsys):
    base = _write(
        tmp_path,
        "base.json",
        {"findings": [_entry("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf")]},
    )
    rc = _object_scan(
        monkeypatch, tmp_path, tmp_path / "n.json", "--baseline", str(base), "--fail-on-any"
    )
    capsys.readouterr()
    doc = json.loads((tmp_path / "n.json").read_text())
    assert rc == 1
    assert [f["check_id"] for f in doc["baselined"]] == ["CKV_AWS_16"]
    assert all(f["check_id"] != "CKV_AWS_16" for f in doc["findings"])


def test_baseline_without_timestamp_says_date_unknown(monkeypatch, tmp_path, capsys):
    base = _write(
        tmp_path, "base.json", [_entry("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf")]
    )
    _object_scan(monkeypatch, tmp_path, tmp_path / "n.json", "--baseline", str(base))
    assert "1 finding(s) match the baseline (date unknown)" in capsys.readouterr().err


def test_bad_baseline_exits_2(monkeypatch, tmp_path, capsys):
    base = _write(tmp_path, "base.json", {"foo": 1})
    assert _object_scan(monkeypatch, tmp_path, tmp_path / "n.json", "--baseline", str(base)) == 2
    assert _object_scan(monkeypatch, tmp_path, tmp_path / "n.json", "--baseline", "nope.json") == 2


@pytest.mark.parametrize("output", ["dev", "security", "auditor", "sarif"])
def test_baselined_shown_in_every_report(monkeypatch, tmp_path, capsys, output):
    base = _write(tmp_path, "b.json", [_entry("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf")])
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(_abs(FIXTURE)), "--output", output,
                 "--output-dir", str(tmp_path / "r"), "--baseline", str(base))  # fmt: skip
    out = capsys.readouterr().out
    assert rc == 0
    if output == "dev":
        assert "Known (in baseline)" in out
    elif output == "sarif":
        results = json.loads(out)["runs"][0]["results"]
        states = {r["ruleId"]: r.get("baselineState") for r in results if r.get("kind") != "x"}
        assert states["CKV_AWS_16"] == "unchanged"
        assert states["CKV_AWS_18"] == "new"
    else:
        html = next((tmp_path / "r").glob("*.html")).read_text()
        assert "Known (in baseline)" in html


def test_sarif_without_baseline_has_no_baseline_state(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(_abs(FIXTURE)), "--output", "sarif")
    assert "baselineState" not in capsys.readouterr().out


def _diff_files(tmp_path):
    old = _write(tmp_path, "old.json", {"findings": [_entry("A", "r1"), _entry("B", "r2")]})
    new = _write(
        tmp_path, "new.json", {"findings": [_entry("B", "r2", "s3.tf"), _entry("C", "r3")]}
    )
    return old, new


def test_diff_reports_new_and_fixed(monkeypatch, tmp_path, capsys):
    old, new = _diff_files(tmp_path)
    rc = run_command(monkeypatch, tmp_path, "diff", str(old), str(new))
    out = capsys.readouterr().out
    assert rc == 1
    assert "New: 1" in out and "Fixed: 1" in out and "Unchanged: 1" in out
    assert "C r3" in out and "A r1" in out


def test_diff_identical_exits_0(monkeypatch, tmp_path, capsys):
    old, _ = _diff_files(tmp_path)
    assert run_command(monkeypatch, tmp_path, "diff", str(old), str(old)) == 0
    assert "New: 0" in capsys.readouterr().out


def test_diff_json_output(monkeypatch, tmp_path, capsys):
    old, new = _diff_files(tmp_path)
    rc = run_command(monkeypatch, tmp_path, "diff", str(old), str(new), "--json")
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert doc == {
        "new": [{"check_id": "C", "resource": "r3", "file_path": "/s3.tf"}],
        "fixed": [{"check_id": "A", "resource": "r1", "file_path": "/s3.tf"}],
        "unchanged": 1,
    }


def test_diff_errors_exit_2(monkeypatch, tmp_path, capsys):
    old, _ = _diff_files(tmp_path)
    assert run_command(monkeypatch, tmp_path, "diff", str(old), str(tmp_path / "x.json")) == 2
    assert run_command(monkeypatch, tmp_path, "diff", str(old)) == 2


def test_diff_baseline_report_vs_plain_report_has_no_false_fixed(monkeypatch, tmp_path, capsys):
    base = _write(tmp_path, "b.json", [_entry("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf")])
    a, plain = tmp_path / "a.json", tmp_path / "plain.json"
    _object_scan(monkeypatch, tmp_path, a, "--baseline", str(base))
    _object_scan(monkeypatch, tmp_path, plain)
    capsys.readouterr()
    assert run_command(monkeypatch, tmp_path, "diff", str(a), str(plain)) == 0
    out = capsys.readouterr().out
    assert "Fixed: 0" in out and "New: 0" in out


def test_array_report_with_baselined_entries_works_as_baseline(monkeypatch, tmp_path, capsys):
    base = _write(tmp_path, "b.json", [_entry("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf")])
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(_abs(FIXTURE)), "--output", "json",
            "--baseline", str(base))  # fmt: skip
    array = tmp_path / "arr.json"
    array.write_text(capsys.readouterr().out, encoding="utf-8")
    assert any(e["baselined"] for e in json.loads(array.read_text()))
    assert (
        finding_key("CKV_AWS_16", "aws_db_instance.app_db", "/rds.tf") in load_baseline(array).keys
    )


def test_diff_malformed_shape_exits_2(monkeypatch, tmp_path, capsys):
    old, _ = _diff_files(tmp_path)
    bad = _write(tmp_path, "bad.json", {"findings": [], "scan": "x"})
    assert run_command(monkeypatch, tmp_path, "diff", str(old), str(bad)) == 2


def test_baseline_stderr_count_follows_framework(monkeypatch, tmp_path, capsys):
    base = _write(tmp_path, "base.json", [_entry("CKV_AWS_53", "aws_s3_bucket.logs", "/s3.tf")])
    checkov = tmp_path / "c.json"
    checkov.write_text(
        json.dumps(
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_53",
                            "check_name": "n",
                            "resource": "aws_s3_bucket.logs",
                            "file_path": "/s3.tf",
                            "file_line_range": [1, 2],
                        }
                    ]
                }
            }
        )
    )
    args = ("--checkov-json", str(checkov), "--baseline", str(base), "--output", "json")
    run_cli(monkeypatch, tmp_path, *args, "--framework", "nis2")
    assert "match the baseline" not in capsys.readouterr().err
    run_cli(monkeypatch, tmp_path, *args, "--framework", "gdpr")
    assert "1 finding(s) match the baseline" in capsys.readouterr().err


def _only_unmapped_doc(*check_ids):
    failed = [
        {
            "check_id": cid,
            "check_name": "unmapped check",
            "resource": "aws_x.y",
            "file_path": "/a.tf",
            "file_line_range": [1, 2],
        }
        for cid in check_ids
    ]
    return {
        "check_type": "terraform",
        "results": {"passed_checks": [], "failed_checks": failed, "skipped_checks": []},
        "summary": {"parsing_errors": 0, "resource_count": 1},
    }


def _known_unmapped_scan(monkeypatch, tmp_path, capsys, *extra, new=()):
    """Scan whose only failures are unmapped, rerun against its own object report."""
    source = tmp_path / "in.json"
    source.write_text(json.dumps(_only_unmapped_doc("CKV_ZZZ_999")), encoding="utf-8")
    base = tmp_path / "base.json"
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(source), "--no-config", "--output", "json",
            "--json-format", "object", "--output-file", str(base))  # fmt: skip
    source.write_text(json.dumps(_only_unmapped_doc("CKV_ZZZ_999", *new)), encoding="utf-8")
    capsys.readouterr()
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(source), "--no-config",
            "--baseline", str(base), *extra)  # fmt: skip
    return capsys.readouterr()


def test_sarif_marks_baselined_unmapped_unchanged(monkeypatch, tmp_path, capsys):
    out = _known_unmapped_scan(
        monkeypatch, tmp_path, capsys, "--output", "sarif", new=("CKV_ZZZ_1",)
    )
    results = json.loads(out.out)["runs"][0]["results"]
    states = {r["ruleId"]: r.get("baselineState") for r in results}
    assert states == {"CKV_ZZZ_999": "unchanged", "CKV_ZZZ_1": "new"}


def test_sarif_without_baseline_has_no_state_on_unmapped(monkeypatch, tmp_path, capsys):
    source = tmp_path / "in.json"
    source.write_text(json.dumps(_only_unmapped_doc("CKV_ZZZ_999")), encoding="utf-8")
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(source), "--no-config", "--output", "sarif"
    )
    (result,) = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert "baselineState" not in result


def test_dev_report_with_only_baselined_unmapped_is_not_clean(monkeypatch, tmp_path, capsys):
    out = _known_unmapped_scan(monkeypatch, tmp_path, capsys, "--output", "dev").out
    assert "No compliance findings" not in out
    assert "Known unmapped (in baseline) (1)" in out
    assert "CKV_ZZZ_999" not in out  # listed only with --show-unmapped
    listed = _known_unmapped_scan(
        monkeypatch, tmp_path, capsys, "--output", "dev", "--show-unmapped"
    ).out
    assert "CKV_ZZZ_999" in listed


@pytest.mark.parametrize("output", ["security", "auditor"])
def test_html_with_only_baselined_unmapped_is_not_clean(monkeypatch, tmp_path, capsys, output):
    _known_unmapped_scan(
        monkeypatch, tmp_path, capsys, "--output", output, "--output-dir", str(tmp_path / "r")
    )
    html = next((tmp_path / "r").glob("*.html")).read_text()
    assert "No compliance findings" not in html
    assert "Known unmapped (in baseline) (1)" in html
    assert "CKV_ZZZ_999" not in html


def test_dev_html_with_only_baselined_unmapped_is_not_clean():
    from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report

    entry = {"check_id": "CKV_ZZZ_999", "check_name": "n", "resource": "r", "file_path": "/a.tf"}
    html = generate_dev_html_report([], baselined_unmapped=[entry])
    assert "No compliance findings" not in html
    assert "1 known in baseline" in html and "Known unmapped (in baseline) (1)" in html


def test_csv_lists_baselined_unmapped_rows(monkeypatch, tmp_path, capsys):
    out = _known_unmapped_scan(monkeypatch, tmp_path, capsys, "--output", "csv", new=("CKV_ZZZ_1",))
    rows = {line.split(",")[2]: line.split(",")[0] for line in out.out.splitlines()[1:]}
    assert rows == {"CKV_ZZZ_999": "baselined", "CKV_ZZZ_1": "unmapped"}
