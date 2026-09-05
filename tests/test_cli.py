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
