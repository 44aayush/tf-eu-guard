"""Checkov JSON normalization, validation, and extraction tests."""

import io
import json
from pathlib import Path

import pytest

from tf_eu_guard.checkov_runner import (
    CheckovInputError,
    _normalize_checkov_output,
    extract_failed_checks,
    load_checkov_json,
)

SAMPLE = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_17",
                "check_name": "Ensure all data stored in RDS is not publicly accessible",
                "resource": "aws_db_instance.default",
                "file_path": "/rds.tf",
                "file_line_range": [1, 20],
                "guideline": "https://docs.example/CKV_AWS_17",
            },
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                "resource": "aws_s3_bucket_acl.data",
                "file_path": "/s3.tf",
                "file_line_range": [5, 9],
                "guideline": None,
            },
        ]
    },
    "summary": {"parsing_errors": 0},
}

MULTI_TYPE = [
    {"check_type": "secrets", "results": {"failed_checks": [{"check_id": "CKV_SECRET_1"}]}},
    SAMPLE,
]

K8S_ELEMENT = {
    "check_type": "kubernetes",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_K8S_17",
                "check_name": "Kubernetes check",
                "resource": "Pod/example",
                "file_path": "/pod.yaml",
                "file_line_range": [1, 2],
            }
        ]
    },
}

MIXED_FRAMEWORKS = [SAMPLE, K8S_ELEMENT]


def test_extract_returns_all_failed():
    assert [finding["check_id"] for finding in extract_failed_checks(SAMPLE)] == [
        "CKV_AWS_17",
        "CKV_AWS_20",
    ]


def test_extract_preserves_expected_fields():
    first = extract_failed_checks(SAMPLE)[0]
    assert set(first) == {
        "check_id",
        "check_name",
        "resource",
        "file_path",
        "file_line_range",
        "guideline",
    }
    assert first["file_line_range"] == [1, 20]


def test_extract_empty_failed_checks_is_empty():
    assert extract_failed_checks({"results": {"failed_checks": []}}) == []


def test_extract_missing_results_raises():
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks({})


def test_extract_raw_terraform_plan_raises(repo_root):
    raw_plan = json.loads(
        (repo_root / "examples" / "vulnerable-aws-plan" / "plan.json").read_text()
    )
    assert "format_version" in raw_plan
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks(raw_plan)


def test_extract_results_wrong_type_raises():
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks({"results": "not a dict"})


@pytest.mark.parametrize("failed_checks", ["not a list", {}, ["not an object"], [None]])
def test_extract_failed_checks_requires_list_of_mappings(failed_checks):
    with pytest.raises(ValueError, match="failed_checks"):
        extract_failed_checks({"results": {"failed_checks": failed_checks}})


def test_extract_defaults_line_range_when_absent():
    payload = {"results": {"failed_checks": [{"check_id": "X"}]}}
    with pytest.raises(ValueError, match="missing required field.*file_line_range"):
        extract_failed_checks(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("check_id", None, "check_id must be a non-empty string"),
        ("check_id", "", "check_id must be a non-empty string"),
        ("check_id", "   ", "check_id must be a non-empty string"),
        ("check_name", None, "check_name must be a non-empty string"),
        ("resource", 42, "resource must be a string"),
        ("file_path", None, "file_path must be a string"),
        ("file_line_range", "1-2", "file_line_range must contain"),
        ("file_line_range", (1, 2), "file_line_range must contain"),
        ("file_line_range", [1], "file_line_range must contain"),
        ("file_line_range", [1, "2"], "file_line_range must contain"),
        ("file_line_range", [2, 1], "file_line_range must contain"),
        ("file_line_range", [-1, 2], "file_line_range must contain"),
    ],
)
def test_extract_rejects_malformed_required_finding_fields(field, value, message):
    check = dict(SAMPLE["results"]["failed_checks"][0])
    check[field] = value
    with pytest.raises(ValueError, match=message):
        extract_failed_checks({"results": {"failed_checks": [check]}})


@pytest.mark.parametrize(
    "field", ["check_id", "check_name", "resource", "file_path", "file_line_range"]
)
def test_extract_rejects_missing_required_finding_fields(field):
    check = dict(SAMPLE["results"]["failed_checks"][0])
    del check[field]
    with pytest.raises(ValueError, match=f"missing required field.*{field}"):
        extract_failed_checks({"results": {"failed_checks": [check]}})


def test_normalize_dict_passthrough():
    assert _normalize_checkov_output(SAMPLE) is SAMPLE


def test_normalize_legacy_single_object_without_type_is_supported():
    legacy = {"results": {"failed_checks": [{"check_id": "LEGACY"}]}}
    assert _normalize_checkov_output(legacy, "terraform") is legacy


def test_normalize_single_object_rejects_wrong_type():
    with pytest.raises(ValueError, match="declares check_type.*kubernetes"):
        _normalize_checkov_output(K8S_ELEMENT, "terraform")


def test_normalize_array_picks_terraform():
    picked = _normalize_checkov_output(MULTI_TYPE)
    assert picked["check_type"] == "terraform"
    assert [finding["check_id"] for finding in extract_failed_checks(picked)] == [
        "CKV_AWS_17",
        "CKV_AWS_20",
    ]


def test_normalize_array_picks_requested_iac_type():
    assert _normalize_checkov_output(MIXED_FRAMEWORKS, "terraform")["check_type"] == "terraform"
    assert _normalize_checkov_output(MIXED_FRAMEWORKS, "kubernetes")["check_type"] == "kubernetes"


def test_normalize_mixed_array_kubernetes_ids():
    picked = _normalize_checkov_output(MIXED_FRAMEWORKS, "kubernetes")
    assert [finding["check_id"] for finding in extract_failed_checks(picked)] == ["CKV_K8S_17"]


def test_normalize_defaults_to_terraform():
    assert _normalize_checkov_output(MIXED_FRAMEWORKS)["check_type"] == "terraform"


def test_normalize_missing_requested_type_raises():
    with pytest.raises(ValueError, match="no result object.*kubernetes"):
        _normalize_checkov_output(MULTI_TYPE, "kubernetes")


def test_normalize_legacy_array_without_type_raises():
    data = [{"results": {"failed_checks": [{"check_id": "Z"}]}}]
    with pytest.raises(ValueError, match="no result object"):
        _normalize_checkov_output(data)


def test_normalize_empty_array_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output([])


def test_normalize_bad_shape_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output("not a checkov object")


def test_load_checkov_json_threads_iac_type(tmp_path):
    source = tmp_path / "ckv-mixed.json"
    source.write_text(json.dumps(MIXED_FRAMEWORKS))
    findings = extract_failed_checks(load_checkov_json(source, "kubernetes"))
    assert [finding["check_id"] for finding in findings] == ["CKV_K8S_17"]


def test_load_checkov_json_from_file(tmp_path):
    source = tmp_path / "ckv.json"
    source.write_text(json.dumps(SAMPLE))
    findings = extract_failed_checks(load_checkov_json(source))
    assert [finding["check_id"] for finding in findings] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_load_checkov_json_rejects_directory(tmp_path):
    with pytest.raises(CheckovInputError, match="must be a file"):
        load_checkov_json(tmp_path)


def test_load_checkov_json_permission_error_is_user_input(monkeypatch, tmp_path):
    source = tmp_path / "ckv.json"
    source.write_text("{}")
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError(13, "Permission denied")),
    )
    with pytest.raises(CheckovInputError, match="Cannot read Checkov JSON input"):
        load_checkov_json(source)


def test_load_checkov_json_array_from_file(tmp_path):
    source = tmp_path / "ckv-multi.json"
    source.write_text(json.dumps(MULTI_TYPE))
    findings = extract_failed_checks(load_checkov_json(source))
    assert [finding["check_id"] for finding in findings] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_load_checkov_json_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(SAMPLE)))
    findings = extract_failed_checks(load_checkov_json(Path("-")))
    assert findings[0]["check_id"] == "CKV_AWS_17"


def test_load_checkov_json_real_capture(repo_root):
    capture = repo_root / "tests" / "fixtures" / "checkov-raw-output.json"
    if not capture.exists():
        pytest.skip("tests/fixtures/checkov-raw-output.json not present")
    findings = extract_failed_checks(load_checkov_json(capture))
    assert findings
    assert all(finding["check_id"] for finding in findings)
