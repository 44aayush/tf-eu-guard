"""Tests for the CLI entry point (scan command, exit codes, report formats).

Uses ``--checkov-json`` with the committed fixture so no Checkov run (or
network) is needed — the tests exercise argparse wiring, framework filtering,
report generation and the severity-based exit codes end-to-end.
"""

import json
from pathlib import Path

import pytest

from tf_eu_guard.cli import main

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"
PLAN_FIXTURE = "tests/fixtures/checkov-vulnerable-plan.json"
K8S_FIXTURE = "tests/fixtures/checkov-vulnerable-k8s.json"


def run_cli(monkeypatch, tmp_path, *argv):
    """Invoke main() with argv, chdir'd into tmp_path. Returns exit code."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", *argv])
    return main()


def test_version_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "version"])
    assert main() == 0
    assert "version" in capsys.readouterr().out


def test_scan_defaults_to_cwd(monkeypatch, tmp_path, capsys):
    """No PATH (and no --checkov-json) -> scan the current working directory.

    This is the pre-commit hook contract: with ``pass_filenames: false`` the
    hook invokes ``tf-eu-guard scan --output dev --fail-on-severity HIGH``
    with no positional arguments, so the CLI must default to cwd.
    """
    calls = {}

    def fake_run_checkov(target, iac_type="terraform"):
        calls["target"] = target
        return {"results": {"failed_checks": []}}

    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", fake_run_checkov)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "--output", "json"])
    assert main() == 0
    assert Path(calls["target"]) == Path(".")
    assert json.loads(capsys.readouterr().out) == []


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


def test_scan_invalid_iac_type_exits(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "x/", "--iac-type", "bogus"])
    with pytest.raises(SystemExit):
        main()  # argparse rejects invalid choice with code 2


# --- --iac-type (which IaC language to scan) ---


def test_scan_iac_type_and_framework_both_apply(monkeypatch, tmp_path, repo_root, capsys):
    """--iac-type (what to scan) and --framework (what to report) are independent."""
    k8s_doc = {
        "check_type": "kubernetes",
        "results": {"failed_checks": [
            {
                # a registry-mapped K8s check that cites both frameworks
                "check_id": "EUGUARD_NIS2_001",  # not yet realistic for K8s, but registry-mapped
                "check_name": "check",
                "resource": "Secret/app",
                "file_path": "/secret.yaml",
                "file_line_range": [0, 0],
                "guideline": None,
            },
        ]},
    }
    f = tmp_path / "k8s.json"
    f.write_text(json.dumps([{"check_type": "terraform", "results": {"failed_checks": []}}, k8s_doc]))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f),
                 "--iac-type", "kubernetes", "--framework", "nis2", "--output", "json")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["resource"] == "Secret/app"
    # --framework nis2 keeps findings citing NIS2 (this one cites both NIS2 and GDPR)
    assert any(a["framework"] == "NIS2" for a in data[0]["articles"])
    assert {"NIS2", "GDPR"} == {a["framework"] for a in data[0]["articles"]}


def test_scan_iac_type_selects_matching_element(monkeypatch, tmp_path, repo_root, capsys):
    """A mixed-framework JSON array yields the terraform element when iac_type=terraform."""
    tf_doc = {
        "check_type": "terraform",
        "results": {"failed_checks": [{
            "check_id": "CKV_AWS_18",  # registry-mapped
            "check_name": "check",
            "resource": "aws_x.y",
            "file_path": "/a.tf",
            "file_line_range": [1, 2],
            "guideline": None,
        }]},
    }
    k8s_doc = {
        "check_type": "kubernetes",
        "results": {"failed_checks": [{
            "check_id": "CKV_AWS_18",  # same ID, kubernetes element
            "check_name": "check",
            "resource": "Pod/x",
            "file_path": "/p.yaml",
            "file_line_range": [1, 2],
            "guideline": None,
        }]},
    }
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps([k8s_doc, tf_doc]))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f),
                 "--iac-type", "terraform", "--output", "json")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert [d["resource"] for d in data] == ["aws_x.y"]


def test_scan_terraform_plan_takes_path_not_checkov_json(monkeypatch, tmp_path, capsys):
    """Plan mode scans the plan file directly — no --checkov-json required."""
    calls = {}

    def fake_run_checkov(target, iac_type="terraform"):
        calls["target"], calls["iac_type"] = target, iac_type
        return {
            "check_type": "terraform_plan",
            "results": {"failed_checks": [{
                "check_id": "CKV_AWS_293",  # registry-mapped
                "check_name": "check",
                "resource": "aws_db_instance.main",
                "file_path": "/plan.json",
                "file_line_range": [0, 0],
                "guideline": None,
            }]},
        }

    # cli.py imports run_checkov from checkov_runner at scan time, so
    # patching the module attribute intercepts it.
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", fake_run_checkov)

    plan = tmp_path / "plan.json"
    plan.write_text("{}")  # contents don't matter: run_checkov is stubbed
    rc = run_cli(monkeypatch, tmp_path, str(plan),
                 "--iac-type", "terraform_plan", "--output", "json")
    assert rc == 0
    assert calls["iac_type"] == "terraform_plan"
    assert Path(calls["target"]) == plan
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["resource"] == "aws_db_instance.main"


def test_scan_terraform_plan_fixture(monkeypatch, tmp_path, repo_root, capsys):
    """Plan-mode scan: mapped findings with [0,0] line ranges degrade gracefully."""
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / PLAN_FIXTURE),
                 "--iac-type", "terraform_plan", "--output", "json")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) > 0
    # plan-mode findings keep Terraform resource addresses...
    assert any(f["resource"].startswith("aws_") for f in data)
    # ...and cite both frameworks (same registry entries as source-mode checks)
    assert {a["framework"] for f in data for a in f["articles"]} == {"NIS2", "GDPR"}


def test_scan_kubernetes_fixture(monkeypatch, tmp_path, repo_root, capsys):
    """Kubernetes scan: kind/namespace/name resources, CKV_K8S_* mappings."""
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / K8S_FIXTURE),
                 "--iac-type", "kubernetes", "--output", "json")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) > 0
    # K8s resources render as Kind.namespace.name
    assert any(f["resource"].startswith("Pod.") for f in data)
    # the K8s registry namespace is mapped
    assert any(f["check_id"].startswith("CKV_K8S") or f["check_id"].startswith("CKV2_K8S")
               for f in data)
    # the custom K8s secrets check fires and enriches
    assert any(f["check_id"] == "EUGUARD_NIS2_001" for f in data)


def test_scan_kubernetes_framework_filter(monkeypatch, tmp_path, repo_root, capsys):
    """--framework composes with --iac-type kubernetes."""
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(repo_root / K8S_FIXTURE),
            "--iac-type", "kubernetes", "--framework", "gdpr", "--output", "json")
    data = json.loads(capsys.readouterr().out)
    assert all(any(a["framework"] == "GDPR" for a in f["articles"]) for f in data)


def test_scan_checkov_json_rejects_raw_plan_json(monkeypatch, tmp_path, repo_root, capsys):
    """Feeding a raw terraform show -json plan to --checkov-json must error,
    not silently produce 0 findings (the regression that shipped this bug)."""
    plan = repo_root / "examples" / "vulnerable-aws-plan" / "plan.json"
    if not plan.exists():
        pytest.skip("examples/vulnerable-aws-plan/plan.json not present")
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(plan),
                 "--iac-type", "terraform_plan", "--output", "json")
    assert rc == 1
    err = capsys.readouterr().err
    assert "does not look like Checkov output" in err


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


# --- Unmapped Checkov findings (present-but-unmapped, never silently dropped) ---

UNMAPPED_FIXTURE = "tests/fixtures/checkov-unmapped-tf.json"


def _mixed_doc():
    """One mapped (MEDIUM) + two unmapped failures, Checkov-shaped."""
    return {
        "results": {"failed_checks": [
            {
                "check_id": "CKV_AWS_40",  # registry-mapped, severity MEDIUM
                "check_name": "check",
                "resource": "aws_x.y",
                "file_path": "/a.tf",
                "file_line_range": [1, 2],
                "guideline": None,
            },
            {
                "check_id": "CKV_AWS_10",  # password-policy family: unmapped
                "check_name": "check",
                "resource": "aws_iam_account_password_policy.weak",
                "file_path": "/a.tf",
                "file_line_range": [3, 4],
                "guideline": None,
            },
            {
                "check_id": "CKV_AWS_11",  # unmapped
                "check_name": "check",
                "resource": "aws_iam_account_password_policy.weak",
                "file_path": "/a.tf",
                "file_line_range": [3, 4],
                "guideline": None,
            },
        ]}
    }


def test_unmapped_findings_not_in_json_stdout_but_counted_on_stderr(
    monkeypatch, tmp_path, capsys
):
    """--output json stays a pure mapped-findings array; the unmapped count
    is surfaced on stderr so pipelines parsing stdout are unaffected."""
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps(_mixed_doc()))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f), "--output", "json")
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert [d["check_id"] for d in data] == ["CKV_AWS_40"]
    assert "2 unmapped Checkov finding(s)" in captured.err
    assert "no current EU regulatory mapping" in captured.err


def test_unmapped_only_scan_is_not_reported_clean(monkeypatch, tmp_path, capsys):
    """Mapped-zero + unmapped>0 must not print the 'no findings' success banner."""
    doc = _mixed_doc()
    doc["results"]["failed_checks"] = doc["results"]["failed_checks"][1:]
    f = tmp_path / "unmapped-only.json"
    f.write_text(json.dumps(doc))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f), "--output", "dev")
    assert rc == 0
    out = capsys.readouterr().out
    assert "No compliance findings" not in out
    assert "2 unmapped" in out


def test_unmapped_findings_never_trip_the_gate(monkeypatch, tmp_path, capsys):
    """Documented policy: --fail-on-severity/--fail-on-any consider only mapped
    findings (severity is registry-authored, so unmapped findings have no
    severity to compare). Unmapped findings are surfaced, not gated on."""
    doc = _mixed_doc()
    doc["results"]["failed_checks"] = doc["results"]["failed_checks"][1:]  # unmapped only
    f = tmp_path / "unmapped-only.json"
    f.write_text(json.dumps(doc))
    for gate in (["--fail-on-any"], ["--fail-on-severity", "LOW"]):
        rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f),
                     "--output", "json", *gate)
        assert rc == 0, f"{gate} must not fail on unmapped findings alone"
        err = capsys.readouterr().err
        assert "do not affect this gate" in err


def test_mapped_findings_still_trip_the_gate_alongside_unmapped(
    monkeypatch, tmp_path, capsys
):
    """Mixed scan: the mapped MEDIUM finding fails a LOW gate; the note about
    unmapped findings appears alongside the failure."""
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps(_mixed_doc()))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f),
                 "--output", "json", "--fail-on-severity", "LOW")
    assert rc == 1
    assert "Fail: 1 finding(s)" in capsys.readouterr().err


def test_unmapped_count_in_all_html_reports(monkeypatch, tmp_path, repo_root):
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps(_mixed_doc()))
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(f), "--output", "all")
    assert rc == 0
    htmls = {p.name.split("_")[0]: p.read_text() for p in tmp_path.glob("reports/*.html")}
    assert len(htmls) == 3
    # dev/security show the count in the header; the auditor puts it in the
    # scope & limitations note. All three must carry the "no mapping" caveat.
    for kind, doc in htmls.items():
        assert "no current EU regulatory mapping" in doc, f"{kind} report missing note"
    assert "Unmapped Checkov findings: 2" in htmls["dev"]
    assert "Unmapped Checkov findings: 2" in htmls["scan"]
    assert "<strong>2</strong> failed check(s)" in htmls["auditor"]


def test_unmapped_fixture_regression(monkeypatch, tmp_path, repo_root, capsys):
    """Committed real-Checkov fixture (examples/unmapped-aws): the mapped S3
    findings enrich, the password-policy family is surfaced as unmapped, and
    none of the unmapped IDs leak into the mapped-findings output."""
    fixture = repo_root / UNMAPPED_FIXTURE
    if not fixture.exists():
        pytest.skip(f"{UNMAPPED_FIXTURE} not present")
    rc = run_cli(monkeypatch, tmp_path, "--checkov-json", str(fixture), "--output", "json")
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    # mapped: CKV_AWS_9 + the six S3 checks; unmapped: the six CKV_AWS_1x
    assert {d["check_id"] for d in data} >= {"CKV_AWS_9", "CKV_AWS_145", "CKV_AWS_18"}
    unmapped_family = {f"CKV_AWS_{n}" for n in range(10, 16)}
    assert not unmapped_family & {d["check_id"] for d in data}, \
        "unmapped password-policy IDs must not appear as mapped"
    assert "6 unmapped Checkov finding(s)" in captured.err
