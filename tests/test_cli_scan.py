"""Tests for the CLI entry point (scan command, exit codes, report formats).

Uses ``--checkov-json`` with the committed fixture so no Checkov run (or
network) is needed — the tests exercise argparse wiring, framework filtering,
report generation and the severity-based exit codes end-to-end.
"""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tf_eu_guard.cli import main
from tf_eu_guard.constants import SUPPORTED_IAC_TYPES

FIXTURE = "tests/fixtures/checkov-vulnerable-tf.json"
PLAN_FIXTURE = "tests/fixtures/checkov-vulnerable-plan.json"
K8S_FIXTURE = "tests/fixtures/checkov-vulnerable-k8s.json"
REGION_FIXTURE = "tests/fixtures/region-aliases"
SECRET_SHAPES_FIXTURE = "tests/fixtures/secret-shapes"
SOURCE_ERROR_FIXTURES = (
    "tests/fixtures/invalid-only",
    "tests/fixtures/mixed-valid-invalid",
    "tests/fixtures/empty-directory",
)


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


@pytest.mark.parametrize("fixture", SOURCE_ERROR_FIXTURES)
def test_source_scan_fails_closed_on_incomplete_checkov_output(
    monkeypatch, tmp_path, repo_root, capsys, fixture
):
    """Invalid, mixed, and empty source scans cannot report a clean result."""
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / fixture),
        "--output",
        "json",
        "--fail-on-any",
    )
    assert rc == 3
    error = capsys.readouterr().err
    assert "scanner/runtime failure" in error
    if fixture.endswith("empty-directory"):
        assert "no terraform scan results" in error
    else:
        assert "parsing error" in error


def test_scan_dev_output(monkeypatch, tmp_path, repo_root):
    rc = run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE), "--output", "dev"
    )
    assert rc == 0


def test_scan_json_output(monkeypatch, tmp_path, repo_root, capsys):
    rc = run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE), "--output", "json"
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and len(data) > 0
    assert all("check_id" in f and "articles" in f for f in data)


def test_scan_json_output_is_byte_stable(monkeypatch, tmp_path, repo_root, capsys):
    """The machine-readable JSON contract is stable across repeated scans."""
    outputs = []
    for _ in range(2):
        assert (
            run_cli(
                monkeypatch,
                tmp_path,
                "--checkov-json",
                str(repo_root / FIXTURE),
                "--output",
                "json",
            )
            == 0
        )
        outputs.append(capsys.readouterr().out.encode())
    assert outputs[0] == outputs[1]


def test_region_policy_and_transfer_review_are_distinct_live_cli_findings(
    monkeypatch, tmp_path, repo_root, capsys
):
    """A real Checkov-backed scan keeps EUSC policy separate from Chapter V."""
    fixture = repo_root / REGION_FIXTURE
    rc = run_cli(monkeypatch, tmp_path, str(fixture), "--output", "json")
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)

    def rows(resource):
        return [f for f in findings if f["resource"] == resource]

    frankfurt = rows("aws.frankfurt")
    assert {f["check_id"] for f in frankfurt} == {"EUGUARD_GDPR_001"}
    assert frankfurt[0]["articles"] == [{"framework": "POLICY", "article": "Policy EUSC-001"}]

    virginia = rows("aws.virginia")
    assert {f["check_id"] for f in virginia} == {
        "EUGUARD_GDPR_001",
        "EUGUARD_GDPR_002",
    }
    assert next(f for f in virginia if f["check_id"] == "EUGUARD_GDPR_001")["articles"] == [
        {"framework": "POLICY", "article": "Policy EUSC-001"}
    ]
    assert next(f for f in virginia if f["check_id"] == "EUGUARD_GDPR_002")["articles"] == [
        {"framework": "GDPR", "article": "Art. 44"}
    ]
    assert not rows("aws.sovereign")

    # A GDPR-only report contains the third-country review, not the separate
    # project-policy finding for the commercial EU region.
    run_cli(monkeypatch, tmp_path, str(fixture), "--framework", "gdpr", "--output", "json")
    gdpr_findings = json.loads(capsys.readouterr().out)
    assert {f["resource"] for f in gdpr_findings} == {"aws.london", "aws.zurich", "aws.virginia"}
    assert all(f["check_id"] == "EUGUARD_GDPR_002" for f in gdpr_findings)


def test_secret_shape_fixture_covers_custom_and_stock_checks_live_cli(
    monkeypatch, tmp_path, repo_root, capsys
):
    """Each documented secret shape has an observed mapped CLI finding."""
    fixture = repo_root / SECRET_SHAPES_FIXTURE
    rc = run_cli(monkeypatch, tmp_path, str(fixture), "--output", "json")
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)

    custom_resources = {f["resource"] for f in findings if f["check_id"] == "EUGUARD_NIS2_001"}
    assert custom_resources == {
        "aws_db_instance.database",
        "aws_rds_cluster.rds",
        "aws_redshift_cluster.warehouse",
        "aws_docdb_cluster.documents",
        "aws_elasticache_replication_group.cache",
        "aws_codebuild_project.build",
    }

    stock_replacements = {
        "CKV_AWS_41": "aws.credential_shape",
        "CKV_AWS_46": "aws_instance.user_data_shape",
        "CKV_AWS_45": "aws_lambda_function.environment_shape",
    }
    for check_id, resource in stock_replacements.items():
        assert any(f["check_id"] == check_id and f["resource"] == resource for f in findings)
        assert not any(
            f["check_id"] == "EUGUARD_NIS2_001" and f["resource"] == resource for f in findings
        )


def test_scan_framework_filter_nis2(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--framework",
        "nis2",
    )
    data = json.loads(capsys.readouterr().out)
    assert data
    assert all({a["framework"] for a in f["articles"]} == {"NIS2"} for f in data)


def test_scan_framework_filter_gdpr(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "json",
        "--framework",
        "gdpr",
    )
    data = json.loads(capsys.readouterr().out)
    assert data
    assert all({a["framework"] for a in f["articles"]} == {"GDPR"} for f in data)


def test_framework_filter_excludes_articles_from_all_reporters(
    monkeypatch, tmp_path, repo_root, capsys
):
    args = ("--checkov-json", str(repo_root / FIXTURE), "--framework", "nis2")

    run_cli(monkeypatch, tmp_path, *args, "--output", "dev")
    assert "GDPR" not in capsys.readouterr().out

    run_cli(monkeypatch, tmp_path, *args, "--output", "sarif")
    sarif = json.loads(capsys.readouterr().out)
    assert all(
        all(article.startswith("NIS2 ") for article in result["properties"]["articles"])
        for result in sarif["runs"][0]["results"]
        if result["properties"].get("mapped")
    )

    run_cli(monkeypatch, tmp_path, *args, "--output", "all")
    for report in tmp_path.glob("reports/*.html"):
        assert "GDPR Art." not in report.read_text(encoding="utf-8")


def test_scan_html_reports(monkeypatch, tmp_path, repo_root):
    for _ in range(2):
        rc = run_cli(
            monkeypatch, tmp_path, "--checkov-json", str(repo_root / FIXTURE), "--output", "all"
        )
        assert rc == 0
    htmls = list(tmp_path.glob("reports/*.html"))
    assert len(htmls) == 6  # two each of dev, security, auditor; no overwrite


@pytest.mark.parametrize("output", ["security", "auditor"])
def test_html_output_file_creates_missing_parent(monkeypatch, tmp_path, repo_root, output):
    out_file = tmp_path / "nested" / output / "report.html"

    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        output,
        "--output-file",
        str(out_file),
    )

    assert rc == 0
    assert out_file.is_file()


def test_concurrent_scans_do_not_overwrite_reports(tmp_path, repo_root):
    cmd = [
        sys.executable,
        "-m",
        "tf_eu_guard.cli",
        "scan",
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "all",
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(
            pool.map(
                lambda _: subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True),
                range(2),
            )
        )
    assert all(run.returncode == 0 for run in runs), [run.stderr for run in runs]
    names = sorted(path.name for path in (tmp_path / "reports").glob("*.html"))
    assert len(names) == 6
    for prefix in ("dev", "scan", "auditor"):
        assert len([name for name in names if name.startswith(f"{prefix}_report_")]) == 2


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
        "results": {
            "failed_checks": [
                {
                    # a registry-mapped K8s check that cites both frameworks
                    "check_id": "EUGUARD_NIS2_002",  # Kubernetes-specific registry mapping
                    "check_name": "check",
                    "resource": "Secret/app",
                    "file_path": "/secret.yaml",
                    "file_line_range": [0, 0],
                    "guideline": None,
                },
            ]
        },
    }
    f = tmp_path / "k8s.json"
    f.write_text(
        json.dumps([{"check_type": "terraform", "results": {"failed_checks": []}}, k8s_doc])
    )
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(f),
        "--iac-type",
        "kubernetes",
        "--framework",
        "nis2",
        "--output",
        "json",
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["resource"] == "Secret/app"
    # --framework nis2 removes the excluded GDPR article from each finding.
    assert {"NIS2"} == {a["framework"] for a in data[0]["articles"]}


def test_scan_iac_type_selects_matching_element(monkeypatch, tmp_path, repo_root, capsys):
    """A mixed-framework JSON array yields the terraform element when iac_type=terraform."""
    tf_doc = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",  # registry-mapped
                    "check_name": "check",
                    "resource": "aws_x.y",
                    "file_path": "/a.tf",
                    "file_line_range": [1, 2],
                    "guideline": None,
                }
            ]
        },
    }
    k8s_doc = {
        "check_type": "kubernetes",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",  # same ID, kubernetes element
                    "check_name": "check",
                    "resource": "Pod/x",
                    "file_path": "/p.yaml",
                    "file_line_range": [1, 2],
                    "guideline": None,
                }
            ]
        },
    }
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps([k8s_doc, tf_doc]))
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(f),
        "--iac-type",
        "terraform",
        "--output",
        "json",
    )
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
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_293",  # registry-mapped
                        "check_name": "check",
                        "resource": "aws_db_instance.main",
                        "file_path": "/plan.json",
                        "file_line_range": [0, 0],
                        "guideline": None,
                    }
                ]
            },
        }

    # cli.py imports run_checkov from checkov_runner at scan time, so
    # patching the module attribute intercepts it.
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", fake_run_checkov)

    plan = tmp_path / "plan.json"
    plan.write_text("{}")  # contents don't matter: run_checkov is stubbed
    rc = run_cli(
        monkeypatch, tmp_path, str(plan), "--iac-type", "terraform_plan", "--output", "json"
    )
    assert rc == 0
    assert calls["iac_type"] == "terraform_plan"
    assert Path(calls["target"]) == plan
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["resource"] == "aws_db_instance.main"


def test_scan_terraform_plan_fixture(monkeypatch, tmp_path, repo_root, capsys):
    """Plan-mode scan: mapped findings with [0,0] line ranges degrade gracefully."""
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / PLAN_FIXTURE),
        "--iac-type",
        "terraform_plan",
        "--output",
        "json",
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) > 0
    # plan-mode findings keep Terraform resource addresses...
    assert any(f["resource"].startswith("aws_") for f in data)
    # ...and cite both frameworks (same registry entries as source-mode checks)
    assert {a["framework"] for f in data for a in f["articles"]} == {"NIS2", "GDPR"}


def test_scan_kubernetes_fixture(monkeypatch, tmp_path, repo_root, capsys):
    """Kubernetes scan: kind/namespace/name resources, CKV_K8S_* mappings."""
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / K8S_FIXTURE),
        "--iac-type",
        "kubernetes",
        "--output",
        "json",
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) > 0
    # K8s resources render as Kind.namespace.name
    assert any(f["resource"].startswith("Pod.") for f in data)
    # the K8s registry namespace is mapped
    assert any(
        f["check_id"].startswith("CKV_K8S") or f["check_id"].startswith("CKV2_K8S") for f in data
    )
    # the custom K8s secrets check fires and enriches
    assert any(f["check_id"] == "EUGUARD_NIS2_002" for f in data)


def test_scan_kubernetes_framework_filter(monkeypatch, tmp_path, repo_root, capsys):
    """--framework composes with --iac-type kubernetes."""
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / K8S_FIXTURE),
        "--iac-type",
        "kubernetes",
        "--framework",
        "gdpr",
        "--output",
        "json",
    )
    data = json.loads(capsys.readouterr().out)
    assert all(any(a["framework"] == "GDPR" for a in f["articles"]) for f in data)


def test_cli_iac_type_choices_match_constants(monkeypatch, tmp_path, capsys):
    """--iac-type choices must equal SUPPORTED_IAC_TYPES verbatim — the
    constants module is the single source of truth, and a hand-retyped
    choices list is exactly how the CLI and the scanner drift apart."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["tf-eu-guard", "scan", "x/", "--iac-type", "bogus"])
    with pytest.raises(SystemExit) as exc:
        main()  # argparse rejects the bogus choice with code 2
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice: 'bogus'" in err
    # The usage line renders the choices metavar as {a,b,c} — stable across
    # Python versions, unlike the error text whose quoting format changed
    # in 3.14. Asserting it against SUPPORTED_IAC_TYPES keeps the constants
    # module the single source of truth.
    expected_metavar = "{" + ",".join(SUPPORTED_IAC_TYPES) + "}"
    assert f"--iac-type {expected_metavar}" in err
