"""Reviewed waiver file (N-01): loading, matching, gating and reporting."""

import json
from datetime import date, timedelta

import pytest
from cli_helpers import EUGUARD_PASSED, run_cli

from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework
from tf_eu_guard.waivers import Waiver, WaiverError, apply_waivers, load_waivers

TODAY = date(2026, 6, 1)
HEADER = "schema_version: 1\nwaivers:\n"
GOOD = (
    "  - check_id: CKV_AWS_18\n    resource: aws_s3_bucket.logs\n    owner: platform-team\n"
    "    reason: Access logs bucket.\n    expires: 2027-03-31\n"
)


def _finding(check_id="CKV_AWS_18", resource="aws_s3_bucket.logs", path="/modules/a/main.tf"):
    return EnrichedFinding(
        check_id=check_id,
        check_name="n",
        resource=resource,
        file_path=path,
        file_line_range=[1, 2],
        guideline=None,
        articles=[ArticleReference(Framework.NIS2, "Art. 21(2)(h)", "t")],
    )


def _waiver(**kw):
    base = dict(
        check_id="CKV_AWS_18",
        resource="aws_s3_bucket.logs",
        owner="o",
        reason="r",
        expires=date(2027, 3, 31),
    )
    return Waiver(**{**base, **kw})


def _write(tmp_path, text, name="w.yaml"):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_load_waivers_valid(tmp_path):
    path = _write(tmp_path, HEADER + GOOD + '    file: "modules/**/*.tf"\n')
    assert load_waivers(path) == [
        _waiver(owner="platform-team", reason="Access logs bucket.", file="modules/**/*.tf")
    ]


def test_load_waivers_accepts_iso_string_date(tmp_path):
    path = _write(tmp_path, HEADER + GOOD.replace("2027-03-31", '"2027-03-31"'))
    assert load_waivers(path)[0].expires == date(2027, 3, 31)


@pytest.mark.parametrize(
    "text",
    [
        HEADER + GOOD.replace("    owner: platform-team\n", ""),
        HEADER + GOOD + "    surprise: 1\n",
        HEADER + GOOD.replace("2027-03-31", "next tuesday"),
        "schema_version: 2\nwaivers:\n" + GOOD,
        HEADER + GOOD.replace("Access logs bucket.", '""'),
        HEADER + GOOD.replace("owner: platform-team", "owner: ' '"),
        "",
        "waivers: []\n",
        "schema_version: 1\nwaivers: nope\n",
        HEADER
        + GOOD
        + GOOD.replace("  - check_id", "  - check_id", 1).replace(
            "owner: platform-team", "owner: a\n    owner: b"
        ),
        "key: [unclosed\n",
    ],
)
def test_load_waivers_rejects(tmp_path, text):
    with pytest.raises(WaiverError):
        load_waivers(_write(tmp_path, text))


def test_apply_waivers_matches_check_and_resource():
    hit, other_check, other_res = (
        _finding(),
        _finding("CKV_AWS_19"),
        _finding(resource="aws_s3_bucket.x"),
    )
    result = apply_waivers([hit, other_check, other_res], [_waiver()], TODAY)
    assert [f.check_id for f in result.waived] == ["CKV_AWS_18"]
    assert result.waived[0].waiver == _waiver()
    assert result.active == [other_check, other_res]
    assert result.expired == [] and result.unused == []


def test_apply_waivers_file_glob():
    waiver = _waiver(file="modules/**/*.tf")
    inside = _finding(path="/modules/a/main.tf")
    outside = _finding(path="/root/main.tf")
    windows = _finding(path="\\modules\\b\\main.tf")
    result = apply_waivers([inside, outside, windows], [waiver], TODAY)
    assert [f.file_path for f in result.waived] == [inside.file_path, windows.file_path]
    assert [f.file_path for f in result.active] == ["/root/main.tf"]


def test_expired_waiver_reactivates_finding():
    waiver = _waiver(expires=date(2026, 5, 31))
    result = apply_waivers([_finding()], [waiver], TODAY)
    assert len(result.active) == 1 and result.waived == []
    assert result.expired == [waiver]
    assert result.unused == []


def test_waiver_expiring_today_still_valid():
    result = apply_waivers([_finding()], [_waiver(expires=TODAY)], TODAY)
    assert len(result.waived) == 1 and result.expired == []


def test_unused_waiver_reported():
    waiver = _waiver(resource="aws_s3_bucket.nothing")
    result = apply_waivers([_finding()], [waiver], TODAY)
    assert result.unused == [waiver] and len(result.active) == 1


# --- CLI ---------------------------------------------------------------------


def _doc(failed=(), skipped=()):
    def check(cid, resource):
        return {
            "check_id": cid,
            "check_name": "check",
            "resource": resource,
            "file_path": "/main.tf",
            "file_line_range": [1, 2],
            "guideline": None,
        }

    return {
        "results": {
            "passed_checks": [EUGUARD_PASSED],
            "failed_checks": [check(*c) for c in failed],
            "skipped_checks": [
                {**check(*c), "check_result": {"result": "SKIPPED"}} for c in skipped
            ],
        }
    }


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    monkeypatch.setattr("tf_eu_guard.cli.pipeline._today", lambda: TODAY)


def _setup(tmp_path, failed=(), skipped=(), waivers=HEADER + GOOD):
    checkov = tmp_path / "c.json"
    checkov.write_text(json.dumps(_doc(failed, skipped)))
    wfile = _write(tmp_path, waivers)
    return ["--checkov-json", str(checkov), "--waivers", str(wfile)]


LOGS = ("CKV_AWS_18", "aws_s3_bucket.logs")


def test_waived_findings_listed_on_stderr_and_in_json(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS])
    rc = run_cli(
        monkeypatch, tmp_path, *args, "--fail-on-any", "--output", "json", "--json-format", "object"
    )
    out = capsys.readouterr()
    assert rc == 0
    assert "1 finding(s) waived by" in out.err
    doc = json.loads(out.out)
    assert doc["findings"] == []
    assert doc["waived"][0]["check_id"] == "CKV_AWS_18"
    assert doc["waived"][0]["waiver"] == {
        "owner": "platform-team",
        "reason": "Access logs bucket.",
        "expires": "2027-03-31",
        "file": None,
    }
    assert doc["summary"]["total"] == 0


def test_json_array_marks_waived(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS, ("CKV_AWS_40", "aws_x.y")])
    run_cli(monkeypatch, tmp_path, *args, "--output", "json")
    rows = {r["check_id"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["CKV_AWS_18"]["waived"] is True
    assert rows["CKV_AWS_40"]["waived"] is False


def test_requirement_matrix_counts_waived(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS])
    run_cli(monkeypatch, tmp_path, *args, "--output", "json", "--json-format", "object")
    doc = json.loads(capsys.readouterr().out)
    assert sum(r["waived"] for r in doc["requirements"]) >= 1


def test_expired_waiver_warns_and_keeps_finding_active(monkeypatch, tmp_path, capsys):
    args = _setup(
        tmp_path, failed=[LOGS], waivers=HEADER + GOOD.replace("2027-03-31", "2026-01-01")
    )
    rc = run_cli(monkeypatch, tmp_path, *args, "--fail-on-any")
    err = capsys.readouterr().err
    assert rc == 1
    assert (
        "Waiver expired on 2026-01-01: CKV_AWS_18 aws_s3_bucket.logs (owner platform-team)" in err
    )


def test_unused_waiver_warns(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[("CKV_AWS_40", "aws_x.y")])
    run_cli(monkeypatch, tmp_path, *args)
    err = capsys.readouterr().err
    assert "matched nothing" in err and "CKV_AWS_18 aws_s3_bucket.logs" in err


def test_waived_listed_in_dev_terminal(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS])
    run_cli(monkeypatch, tmp_path, *args)
    out = capsys.readouterr().out
    assert "Waived" in out and "platform-team" in out and "Access logs bucket." in out


def test_waived_listed_and_escaped_in_html(monkeypatch, tmp_path):
    waivers = HEADER + GOOD.replace("Access logs bucket.", "'<script>alert(1)</script>'")
    args = _setup(tmp_path, failed=[LOGS], waivers=waivers)
    run_cli(monkeypatch, tmp_path, *args, "--output", "all", "--output-dir", str(tmp_path / "r"))
    pages = list((tmp_path / "r").glob("*.html"))
    assert len(pages) == 3
    for page in pages:
        text = page.read_text()
        assert "Waived" in text and "platform-team" in text
        assert "<script>alert(1)" not in text


def test_inline_skip_with_waiver_does_not_trip_fail_on_suppressed(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, skipped=[LOGS])
    rc = run_cli(
        monkeypatch, tmp_path, *args, "--fail-on-suppressed", "--output", "json",
        "--json-format", "object",
    )  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert [w["check_id"] for w in doc["waived"]] == ["CKV_AWS_18"]
    assert doc["summary"]["suppressed"] == 0


def test_inline_skip_without_waiver_still_trips_fail_on_suppressed(monkeypatch, tmp_path):
    args = _setup(tmp_path, skipped=[("CKV_AWS_18", "aws_s3_bucket.other")])
    assert run_cli(monkeypatch, tmp_path, *args, "--fail-on-suppressed") == 1


def test_waiver_file_discovered_in_scan_root(monkeypatch, tmp_path, capsys, repo_root):
    pytest.importorskip("checkov")
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / "tests/fixtures/waiver-discovery"),
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    out = capsys.readouterr()
    assert rc == 0
    doc = json.loads(out.out)
    assert any(w["check_id"] == "CKV_AWS_18" for w in doc["waived"])
    assert all(f["check_id"] != "CKV_AWS_18" for f in doc["findings"])
    assert "waived by" in out.err


def test_explicit_config_disables_waiver_discovery(monkeypatch, tmp_path, capsys, repo_root):
    pytest.importorskip("checkov")
    cfg = tmp_path / "trusted.yaml"
    cfg.write_text("{}\n", encoding="utf-8")
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / "tests/fixtures/waiver-discovery"),
        "--config", str(cfg), "--output", "json", "--json-format", "object",
    )  # fmt: skip
    out = capsys.readouterr()
    assert rc == 0
    doc = json.loads(out.out)
    assert doc["waived"] == []
    assert any(f["check_id"] == "CKV_AWS_18" for f in doc["findings"])
    assert "waived by" not in out.err


def test_checkov_json_without_flag_discovers_nothing(monkeypatch, tmp_path, capsys):
    _write(tmp_path, HEADER + GOOD, ".tf-eu-guard-waivers.yaml")
    checkov = tmp_path / "c.json"
    checkov.write_text(json.dumps(_doc([LOGS])))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(checkov), "--fail-on-any")
    assert rc == 1 and "waived by" not in capsys.readouterr().err


def test_bad_waiver_file_exits_2(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS], waivers="schema_version: 9\n")
    assert run_cli(monkeypatch, tmp_path, *args) == 2


def test_missing_waiver_file_exits_2(monkeypatch, tmp_path):
    args = _setup(tmp_path, failed=[LOGS])
    args[-1] = str(tmp_path / "nope.yaml")
    assert run_cli(monkeypatch, tmp_path, *args) == 2


def test_sarif_waived_result_has_external_suppression(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS])
    run_cli(monkeypatch, tmp_path, *args, "--output", "sarif")
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert results[0]["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": "Access logs bucket. (owner platform-team, expires 2027-03-31)",
        }
    ]


def test_json_object_with_waived_validates_against_schema(monkeypatch, tmp_path, capsys, repo_root):
    jsonschema = pytest.importorskip("jsonschema")
    args = _setup(tmp_path, failed=[LOGS])
    run_cli(monkeypatch, tmp_path, *args, "--output", "json", "--json-format", "object")
    schema = json.loads((repo_root / "tf_eu_guard/schemas/report.schema.json").read_text())
    document = json.loads(capsys.readouterr().out)
    jsonschema.validate(document, schema)
    del document["waived"][0]["waiver"]["owner"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, schema)


def test_load_waivers_rejects_duplicate_unhashable_key(tmp_path):
    path = _write(tmp_path, "? [a]\n: 1\n? [a]\n: 2\n")
    with pytest.raises(WaiverError):
        load_waivers(path)


def test_load_waivers_unreadable_path_is_waiver_error(tmp_path):
    with pytest.raises(WaiverError):
        load_waivers(tmp_path)


def test_waivers_directory_exits_2(monkeypatch, tmp_path):
    args = _setup(tmp_path, failed=[LOGS])
    args[-1] = str(tmp_path)
    assert run_cli(monkeypatch, tmp_path, *args) == 2


def test_waived_stderr_count_follows_framework(monkeypatch, tmp_path, capsys):
    gdpr_only = ("CKV_AWS_53", "aws_s3_bucket.logs")
    waivers = HEADER + GOOD.replace("CKV_AWS_18", "CKV_AWS_53")
    args = _setup(tmp_path, failed=[gdpr_only], waivers=waivers)
    run_cli(monkeypatch, tmp_path, *args, "--framework", "nis2", "--output", "json")
    assert "finding(s) waived" not in capsys.readouterr().err
    run_cli(monkeypatch, tmp_path, *args, "--framework", "gdpr", "--output", "json")
    assert "1 finding(s) waived by" in capsys.readouterr().err


def _source_root(monkeypatch, tmp_path):
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: _doc([LOGS]))
    src = tmp_path / "src"
    src.mkdir()
    return src


def test_no_discovery_ignores_scan_root_waivers(monkeypatch, tmp_path, capsys):
    src = _source_root(monkeypatch, tmp_path)
    _write(src, HEADER + GOOD, ".tf-eu-guard-waivers.yaml")
    assert run_cli(monkeypatch, tmp_path, str(src), "--fail-on-any") == 0
    capsys.readouterr()
    assert run_cli(monkeypatch, tmp_path, str(src), "--fail-on-any", "--no-discovery") == 1
    err = capsys.readouterr().err
    assert f"Note: --no-discovery: ignored {src / '.tf-eu-guard-waivers.yaml'}" in err


def test_no_discovery_keeps_explicit_waivers_and_config(monkeypatch, tmp_path, capsys):
    src = _source_root(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    wfile = _write(outside, HEADER + GOOD, "w.yaml")
    rc = run_cli(
        monkeypatch, tmp_path, str(src), "--fail-on-any", "--no-discovery", "--waivers", str(wfile)
    )
    assert rc == 0
    cfg = _write(outside, f"waivers: {wfile}\n", "c.yaml")
    rc = run_cli(
        monkeypatch, tmp_path, str(src), "--fail-on-any", "--no-discovery", "--config", str(cfg)
    )
    assert rc == 0
    assert "ignored" not in capsys.readouterr().err


# --- bounds (TEG-01) -----------------------------------------------------------


def test_waiver_beyond_max_days_is_not_applied():
    waiver = _waiver(expires=TODAY + timedelta(days=400))
    result = apply_waivers([_finding()], [waiver], TODAY, max_days=365)
    assert len(result.active) == 1 and not result.waived
    assert result.too_long == [waiver]


def test_waiver_within_max_days_applies():
    waiver = _waiver(expires=TODAY + timedelta(days=365))
    result = apply_waivers([_finding()], [waiver], TODAY, max_days=365)
    assert len(result.waived) == 1 and not result.active
    assert result.too_long == []


def test_long_waiver_applies_without_limit():
    result = apply_waivers([_finding()], [_waiver(expires=date(9999, 12, 31))], TODAY)
    assert len(result.waived) == 1 and result.too_long == []


def test_cli_max_waiver_days_trips_gate(monkeypatch, tmp_path, capsys):
    waiver = (
        "  - check_id: CKV_AWS_16\n    resource: aws_db_instance.app_db\n    owner: o\n"
        "    reason: r\n    expires: 9999-12-31\n    file: main.tf\n"
    )
    args = _setup(
        tmp_path, failed=[("CKV_AWS_16", "aws_db_instance.app_db")], waivers=HEADER + waiver
    )
    rc = run_cli(
        monkeypatch, tmp_path, *args, "--fail-on-severity", "HIGH", "--max-waiver-days", "90"
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert (
        "Warning: waiver for CKV_AWS_16 aws_db_instance.app_db expires 9999-12-31, "
        "more than 90 days ahead (--max-waiver-days); not applied" in err
    )
    # Without the limit the same waiver clears the gate.
    assert run_cli(monkeypatch, tmp_path, *args, "--fail-on-severity", "HIGH") == 0


def test_cli_max_waiver_days_rejects_zero(monkeypatch, tmp_path):
    args = _setup(tmp_path, failed=[LOGS])
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, tmp_path, *args, "--max-waiver-days", "0")
    assert exc.value.code == 2


def test_waiver_without_file_warns(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS])
    run_cli(monkeypatch, tmp_path, *args)
    err = capsys.readouterr().err
    assert (
        "Warning: waiver for CKV_AWS_18 aws_s3_bucket.logs has no file pattern; "
        "it matches that resource in every file" in err
    )


def test_waiver_with_file_does_not_warn_about_pattern(monkeypatch, tmp_path, capsys):
    args = _setup(tmp_path, failed=[LOGS], waivers=HEADER + GOOD + '    file: "*.tf"\n')
    run_cli(monkeypatch, tmp_path, *args)
    assert "no file pattern" not in capsys.readouterr().err
