"""EUGUARD_POLICY_005: a registry-backed finding for AWS stacks with no provider region (TEG-05)."""

import importlib.util
import json
import os
from datetime import date
from pathlib import Path

import pytest
from cli_helpers import run_cli

from tf_eu_guard.mapping.loader import load_registry
from tf_eu_guard.residency import (
    aws_region_unset_finding,
    aws_region_unset_warning,
    gcp_region_unset_finding,
    gcp_region_unset_warning,
)

requires_checkov = pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or importlib.util.find_spec("checkov") is None,
    reason="live Checkov test: set TFEG_RUN_CHECKOV=1 with Checkov installed",
)

NO_REGION_TF = (
    'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'
    'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n'
)


def _scan_json(monkeypatch, tmp_path, capsys, *extra):
    code = run_cli(
        monkeypatch, tmp_path, str(tmp_path), "--no-config", "--output", "json",
        "--json-format", "object", *extra,
    )  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def _policy_005(report):
    return [f for f in report["findings"] if f["check_id"] == "EUGUARD_POLICY_005"]


@requires_checkov
def test_no_region_finding_on_source_scan(monkeypatch, tmp_path, capsys):
    (tmp_path / "main.tf").write_text(NO_REGION_TF)
    code, report = _scan_json(monkeypatch, tmp_path, capsys)
    found = _policy_005(report)
    assert len(found) == 1
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["resource"] == "provider.aws"
    assert code in (0, 1)
    code, _ = _scan_json(monkeypatch, tmp_path, capsys, "--fail-on-severity", "MEDIUM")
    assert code == 1


@requires_checkov
def test_no_region_finding_absent_with_region(monkeypatch, tmp_path, capsys):
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n  region = "eu-central-1"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n'
    )
    _, report = _scan_json(monkeypatch, tmp_path, capsys)
    assert _policy_005(report) == []


@requires_checkov
def test_no_region_finding_absent_with_aliased_provider(monkeypatch, tmp_path, capsys):
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n  alias  = "eu"\n  region = "eu-west-1"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n'
    )
    _, report = _scan_json(monkeypatch, tmp_path, capsys)
    assert _policy_005(report) == []


def _output(*, extra_passed=(), resources=("aws_s3_bucket.b",)):
    return {
        "results": {
            "passed_checks": [
                {
                    "check_id": "EUGUARD_GDPR_002",
                    "resource": "aws_s3_bucket.b",
                    "file_path": "/z.tf",
                    "file_line_range": [3, 4],
                },
                *extra_passed,
            ],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "n",
                    "resource": r,
                    "file_path": path,
                    "file_line_range": [line, line + 1],
                }
                for r, path, line in zip(resources, ["/z.tf", "/a.tf"], [3, 9])
            ],
            "skipped_checks": [],
        }
    }


def _live_scan_with_fake_checkov(monkeypatch, tmp_path, capsys, iac_type):
    """Run a live scan whose Checkov run reports AWS resources and no region result.

    A live scan passes custom_checks_loaded=True, so only the iac_type guard in the pipeline
    keeps the finding out of non-Terraform-source scans.
    """
    output = _output()
    output["check_type"] = iac_type
    output["summary"] = {"failed": 1, "passed": 1, "skipped": 0, "parsing_errors": 0}
    output["summary"]["resource_count"] = 1
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: output)
    for check in output["results"]["passed_checks"]:
        check["check_name"] = "n"
    run_cli(
        monkeypatch, tmp_path, str(tmp_path), "--no-config", "--iac-type", iac_type,
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    return json.loads(capsys.readouterr().out)


def test_no_region_finding_present_for_fake_terraform_source_scan(monkeypatch, tmp_path, capsys):
    """Positive control for the cases below: the same fake output does yield the finding."""
    report = _live_scan_with_fake_checkov(monkeypatch, tmp_path, capsys, "terraform")
    assert len(_policy_005(report)) == 1


@pytest.mark.parametrize("iac_type", ["terraform_plan", "kubernetes"])
def test_no_region_finding_absent_in_plan_mode(monkeypatch, tmp_path, capsys, iac_type):
    report = _live_scan_with_fake_checkov(monkeypatch, tmp_path, capsys, iac_type)
    assert report["findings"]
    assert _policy_005(report) == []


@pytest.mark.parametrize(
    "output,loaded",
    [
        (_output(), False),
        (_output(), True),
        (_output(extra_passed=[{"check_id": "EUGUARD_POLICY_001", "resource": "aws.default"}]), False),
        (_output(extra_passed=[{"check_id": "EUGUARD_POLICY_001", "resource": "aws.default"}]), True),
        (
            {"results": {"passed_checks": [], "failed_checks": [
                {"check_id": "CKV_AWS_18", "resource": "aws_s3_bucket.b"}], "skipped_checks": []}},
            False,
        ),
        (
            {"results": {"passed_checks": [], "failed_checks": [
                {"check_id": "CKV_AWS_18", "resource": "aws_s3_bucket.b"}], "skipped_checks": []}},
            True,
        ),
        ({"results": {"failed_checks": [{"check_id": "CKV_GCP_1", "resource": "google_x.b"}]}}, True),
        ({"results": {}}, True),
    ],
)  # fmt: skip
def test_no_region_finding_matches_warning(output, loaded):
    warning = aws_region_unset_warning(output, custom_checks_loaded=loaded)
    finding = aws_region_unset_finding(output, custom_checks_loaded=loaded)
    assert (finding is not None) == (warning is not None)
    if finding is not None:
        assert finding["check_id"] == "EUGUARD_POLICY_005"
        assert finding["resource"] == "provider.aws"


def test_no_region_finding_anchors_at_first_resource_by_location():
    finding = aws_region_unset_finding(_output(resources=("aws_s3_bucket.b", "aws_sqs_queue.q")))
    assert finding is not None
    assert finding["file_path"] == "/a.tf"
    assert finding["file_line_range"] == [9, 10]


def test_no_region_finding_suppressed_by_existing_policy_001_result():
    """A Checkov JSON that already carries a policy-001 result (or skip) yields no finding.

    The finding follows the same predicate as the warning: an existing EUGUARD_POLICY_001
    result, even a skipped one, means a region was evaluated, so nothing is injected.
    """
    output = _output()
    output["results"]["skipped_checks"].append(
        {"check_id": "EUGUARD_POLICY_001", "resource": "aws.default"}
    )
    assert aws_region_unset_finding(output, custom_checks_loaded=True) is None


def _checkov_json(tmp_path):
    document = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [
                {
                    "check_id": "EUGUARD_GDPR_002",
                    "check_name": "n",
                    "resource": "aws_s3_bucket.b",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 2],
                    "check_result": {"result": "PASSED"},
                }
            ],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure the S3 bucket has access logging enabled",
                    "resource": "aws_s3_bucket.b",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 2],
                    "check_result": {"result": "FAILED"},
                }
            ],
            "skipped_checks": [],
        },
        "summary": {
            "failed": 1,
            "passed": 1,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 1,
        },
    }
    path = tmp_path / "checkov.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_no_region_finding_waivable_and_baselined(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("tf_eu_guard.cli.pipeline._today", lambda: date(2026, 6, 1))
    document = _checkov_json(tmp_path)
    base = [
        "--checkov-json",
        document,
        "--no-config",
        "--output",
        "json",
        "--json-format",
        "object",
    ]
    code = run_cli(monkeypatch, tmp_path, *base, "--fail-on-severity", "MEDIUM")
    first = capsys.readouterr().out
    assert code == 1
    assert "EUGUARD_POLICY_005" in first

    waivers = tmp_path / "w.yaml"
    waivers.write_text(
        "schema_version: 1\nwaivers:\n  - check_id: EUGUARD_POLICY_005\n"
        "    resource: provider.aws\n    owner: platform\n    reason: Region set by CI env.\n"
        "    expires: 2027-03-31\n"
    )
    code = run_cli(
        monkeypatch, tmp_path, *base, "--waivers", str(waivers), "--fail-on-severity", "MEDIUM"
    )
    report = json.loads(capsys.readouterr().out)
    assert [w["check_id"] for w in report["waived"]] == ["EUGUARD_POLICY_005"]
    assert code == 1  # CKV_AWS_18 still fails; the region finding no longer does
    assert all(f["check_id"] != "EUGUARD_POLICY_005" for f in report["findings"])

    baseline = tmp_path / "baseline.json"
    baseline.write_text(first)
    code = run_cli(
        monkeypatch, tmp_path, *base, "--baseline", str(baseline), "--fail-on-severity", "MEDIUM"
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert "EUGUARD_POLICY_005" in [f["check_id"] for f in report["baselined"]]


def _resources_output(*resources, passed=("EUGUARD_GDPR_002",)):
    return {
        "results": {
            "passed_checks": [{"check_id": c, "resource": "x.y"} for c in passed],
            "failed_checks": [
                {
                    "check_id": "CKV_X_1",
                    "resource": r,
                    "file_path": "/a.tf",
                    "file_line_range": [1, 2],
                }
                for r in resources
            ],
            "skipped_checks": [],
        }
    }


def test_module_named_aws_bridge_wrapping_gcp_has_no_aws_finding():
    # Only the resource-type segment counts: a module called aws_bridge is not an AWS resource.
    output = _resources_output("module.aws_bridge.google_storage_bucket.b")
    assert aws_region_unset_finding(output, custom_checks_loaded=True) is None
    assert aws_region_unset_warning(output, custom_checks_loaded=True) is None


def test_gcp_warning_ignores_module_named_google_wrapping_aws():
    output = _resources_output("module.google_bridge.aws_s3_bucket.b")
    assert gcp_region_unset_warning(output, custom_checks_loaded=True) is None
    assert aws_region_unset_finding(output, custom_checks_loaded=True) is not None


@pytest.mark.parametrize(
    "resource",
    [
        "aws_s3_bucket.b",
        "module.x.aws_s3_bucket.b",
        'module.x["k"].aws_s3_bucket.b',
        "module.x[0].module.y.aws_s3_bucket.b",
        "data.aws_iam_policy_document.d",  # data sources counted before, kept consistent
    ],
)
def test_aws_resource_shapes_still_count(resource):
    output = _resources_output(resource)
    assert aws_region_unset_finding(output, custom_checks_loaded=True) is not None
    assert aws_region_unset_warning(output, custom_checks_loaded=True) is not None


def test_anchor_prefers_root_module_over_external_modules():
    def check(path, line):
        return {
            "check_id": "CKV_AWS_18",
            "resource": "aws_s3_bucket.b",
            "file_path": path,
            "file_line_range": [line, line + 1],
        }

    output = {
        "results": {
            "passed_checks": [{"check_id": "EUGUARD_GDPR_002", "resource": "x.y"}],
            "failed_checks": [
                check("/.external_modules/github.com/o/m/main.tf", 1),
                check("/stack/z_main.tf", 7),
            ],
            "skipped_checks": [],
        }
    }
    finding = aws_region_unset_finding(output, custom_checks_loaded=True)
    assert finding["file_path"] == "/stack/z_main.tf"


def test_check_name_matches_registry():
    registry = load_registry(Path(__file__).resolve().parents[1] / "tf_eu_guard" / "mapping")
    finding = aws_region_unset_finding(_output(), custom_checks_loaded=True)
    assert finding["check_name"] == registry["EUGUARD_POLICY_005"].check_name


# --- EUGUARD_POLICY_006: the GCP counterpart ---


def _policy_006(report):
    return [f for f in report["findings"] if f["check_id"] == "EUGUARD_POLICY_006"]


def _gcp_resources_output(*resources, passed=("EUGUARD_GDPR_005",)):
    output = _resources_output(*resources, passed=passed)
    for check in output["results"]["passed_checks"] + output["results"]["failed_checks"]:
        check.setdefault("check_name", "n")
        check.setdefault("file_path", "/z.tf")
        check.setdefault("file_line_range", [1, 2])
    for check in output["results"]["passed_checks"]:
        check["check_result"] = {"result": "PASSED"}
    for check in output["results"]["failed_checks"]:
        check["check_id"] = "CKV_GCP_62"  # a mapped check, so plan mode still has findings
        check["check_result"] = {"result": "FAILED"}
    output["check_type"] = "terraform"
    output["summary"] = {
        "failed": len(resources),
        "passed": len(passed),
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": len(resources),
    }
    return output


def _live_scan_with_output(monkeypatch, tmp_path, capsys, output, iac_type="terraform"):
    output["check_type"] = iac_type
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: output)
    run_cli(
        monkeypatch, tmp_path, str(tmp_path), "--no-config", "--iac-type", iac_type,
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    "output,loaded",
    [
        (_gcp_resources_output("google_storage_bucket.b"), False),
        (_gcp_resources_output("google_storage_bucket.b"), True),
        (_gcp_resources_output("google_storage_bucket.b", passed=("EUGUARD_POLICY_004",)), False),
        (_gcp_resources_output("google_storage_bucket.b", passed=("EUGUARD_POLICY_004",)), True),
        (_gcp_resources_output("google_storage_bucket.b", passed=()), False),
        (_gcp_resources_output("google_storage_bucket.b", passed=()), True),
        (_gcp_resources_output("module.google_bridge.aws_s3_bucket.b"), True),
        (_gcp_resources_output("module.aws_bridge.google_storage_bucket.b"), True),
        (_gcp_resources_output("aws_s3_bucket.b"), True),
        ({"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "resource": "aws_x.b"}]}}, True),
        ({"results": {}}, True),
    ],
)  # fmt: skip
def test_gcp_no_region_finding_matches_warning(output, loaded):
    warning = gcp_region_unset_warning(output, custom_checks_loaded=loaded)
    finding = gcp_region_unset_finding(output, custom_checks_loaded=loaded)
    assert (finding is not None) == (warning is not None)
    if finding is not None:
        assert finding["check_id"] == "EUGUARD_POLICY_006"
        assert finding["resource"] == "provider.google"


def test_gcp_no_region_finding_anchors_at_root_module_first_resource():
    def check(path, line, resource="google_storage_bucket.b"):
        return {
            "check_id": "CKV_GCP_62",
            "resource": resource,
            "file_path": path,
            "file_line_range": [line, line + 1],
        }

    output = {
        "results": {
            "passed_checks": [{"check_id": "EUGUARD_GDPR_005", "resource": "x.y"}],
            "failed_checks": [
                check("/.external_modules/github.com/o/m/main.tf", 1),
                check("/stack/z_main.tf", 7),
                check("/stack/a_main.tf", 9),
                check("/stack/a_main.tf", 2, "aws_s3_bucket.b"),
            ],
            "skipped_checks": [],
        }
    }
    finding = gcp_region_unset_finding(output, custom_checks_loaded=True)
    assert finding is not None
    assert finding["file_path"] == "/stack/a_main.tf"
    assert finding["file_line_range"] == [9, 10]


def test_gcp_no_region_finding_injected(monkeypatch, tmp_path, capsys):
    output = _gcp_resources_output("google_storage_bucket.b")
    report = _live_scan_with_output(monkeypatch, tmp_path, capsys, output)
    found = _policy_006(report)
    assert len(found) == 1
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["resource"] == "provider.google"
    assert _policy_005(report) == []


def test_gcp_no_region_finding_absent_when_resources_set_location(monkeypatch, tmp_path, capsys):
    output = _gcp_resources_output("google_storage_bucket.b", passed=("EUGUARD_POLICY_004",))
    report = _live_scan_with_output(monkeypatch, tmp_path, capsys, output)
    assert _policy_006(report) == []


def test_both_no_region_findings_once_each(monkeypatch, tmp_path, capsys):
    output = _gcp_resources_output("google_storage_bucket.b", "aws_s3_bucket.b")
    report = _live_scan_with_output(monkeypatch, tmp_path, capsys, output)
    assert len(_policy_005(report)) == 1
    assert len(_policy_006(report)) == 1


@pytest.mark.parametrize("iac_type", ["terraform_plan", "kubernetes"])
def test_gcp_no_region_finding_absent_in_plan_mode(monkeypatch, tmp_path, capsys, iac_type):
    output = _gcp_resources_output("google_storage_bucket.b")
    report = _live_scan_with_output(monkeypatch, tmp_path, capsys, output, iac_type)
    assert report["findings"]
    assert _policy_006(report) == []


def test_gcp_no_region_finding_waivable(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("tf_eu_guard.cli.pipeline._today", lambda: date(2026, 6, 1))
    document = _checkov_json(tmp_path)
    data = json.loads(Path(document).read_text())
    for key in ("passed_checks", "failed_checks"):
        for check in data["results"][key]:
            check["resource"] = "google_storage_bucket.b"
    data["results"]["passed_checks"][0]["check_id"] = "EUGUARD_GDPR_005"
    Path(document).write_text(json.dumps(data))
    waivers = tmp_path / "w.yaml"
    waivers.write_text(
        "schema_version: 1\nwaivers:\n  - check_id: EUGUARD_POLICY_006\n"
        "    resource: provider.google\n    owner: platform\n    reason: Region set by CI env.\n"
        "    expires: 2027-03-31\n"
    )
    base = [
        "--checkov-json",
        document,
        "--no-config",
        "--output",
        "json",
        "--json-format",
        "object",
    ]
    run_cli(monkeypatch, tmp_path, *base)
    assert "EUGUARD_POLICY_006" in [
        f["check_id"] for f in json.loads(capsys.readouterr().out)["findings"]
    ]
    run_cli(monkeypatch, tmp_path, *base, "--waivers", str(waivers))
    report = json.loads(capsys.readouterr().out)
    assert [w["check_id"] for w in report["waived"]] == ["EUGUARD_POLICY_006"]


def test_gcp_check_name_matches_registry():
    registry = load_registry(Path(__file__).resolve().parents[1] / "tf_eu_guard" / "mapping")
    finding = gcp_region_unset_finding(
        _gcp_resources_output("google_x.b"), custom_checks_loaded=True
    )
    assert finding["check_name"] == registry["EUGUARD_POLICY_006"].check_name
    assert registry["EUGUARD_POLICY_006"].severity.name == "MEDIUM"
