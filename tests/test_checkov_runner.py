"""Validate the Checkov runner (tf_eu_guard.checkov_runner).

``extract_failed_checks`` is tested hermetically against a sample payload. The
live ``run_checkov`` smoke test is opt-in (set ``TFEG_RUN_CHECKOV=1`` and have
the ``checkov`` CLI installed) so the default ``pytest`` run stays fast; the
consolidated ``tests/run_all_tests.sh`` enables it automatically when Checkov
is present.
"""

import io
import json
import os
import shutil
from pathlib import Path

import pytest

from tf_eu_guard.checkov_runner import (
    _normalize_checkov_output,
    extract_failed_checks,
    load_checkov_json,
    run_checkov,
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
}


def test_extract_returns_all_failed():
    out = extract_failed_checks(SAMPLE)
    assert [c["check_id"] for c in out] == ["CKV_AWS_17", "CKV_AWS_20"]


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


def test_extract_missing_results_is_empty():
    assert extract_failed_checks({}) == []
    assert extract_failed_checks({"results": {}}) == []


def test_extract_defaults_line_range_when_absent():
    payload = {"results": {"failed_checks": [{"check_id": "X"}]}}
    out = extract_failed_checks(payload)
    assert out[0]["check_id"] == "X"
    assert out[0]["file_line_range"] == [0, 0]


@pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or shutil.which("checkov") is None,
    reason="live Checkov smoke test: set TFEG_RUN_CHECKOV=1 with the checkov CLI installed",
)
def test_run_checkov_live_smoke(vulnerable_stack_dir):
    if not vulnerable_stack_dir.exists():
        pytest.skip("examples/vulnerable-aws/ not present")
    data = run_checkov(vulnerable_stack_dir)
    assert "results" in data
    findings = extract_failed_checks(data)
    assert findings, "expected the vulnerable stack to produce failed checks"
    assert all(f["check_id"] for f in findings)


# --- load_checkov_json / _normalize_checkov_output (external Checkov JSON input) ---

MULTI_TYPE = [
    {"check_type": "secrets", "results": {"failed_checks": [{"check_id": "CKV_SECRET_1"}]}},
    SAMPLE,  # the terraform element — this is the one we want selected
]


def test_normalize_dict_passthrough():
    assert _normalize_checkov_output(SAMPLE) is SAMPLE


def test_normalize_array_picks_terraform():
    picked = _normalize_checkov_output(MULTI_TYPE)
    assert picked["check_type"] == "terraform"
    assert [c["check_id"] for c in extract_failed_checks(picked)] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_normalize_array_falls_back_to_first_object():
    data = [{"results": {"failed_checks": [{"check_id": "Z"}]}}]
    assert _normalize_checkov_output(data)["results"]["failed_checks"][0]["check_id"] == "Z"


def test_normalize_empty_array_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output([])


def test_normalize_bad_shape_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output("not a checkov object")


def test_load_checkov_json_from_file(tmp_path):
    p = tmp_path / "ckv.json"
    p.write_text(json.dumps(SAMPLE))
    out = extract_failed_checks(load_checkov_json(p))
    assert [c["check_id"] for c in out] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_load_checkov_json_array_from_file(tmp_path):
    p = tmp_path / "ckv-multi.json"
    p.write_text(json.dumps(MULTI_TYPE))
    out = extract_failed_checks(load_checkov_json(p))
    assert [c["check_id"] for c in out] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_load_checkov_json_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(SAMPLE)))
    out = extract_failed_checks(load_checkov_json(Path("-")))
    assert out[0]["check_id"] == "CKV_AWS_17"


def test_load_checkov_json_real_capture(repo_root):
    capture = repo_root / "tests" / "fixtures" / "checkov-raw-output.json"
    if not capture.exists():
        pytest.skip("tests/fixtures/checkov-raw-output.json not present")
    findings = extract_failed_checks(load_checkov_json(capture))
    assert findings, "expected the captured scan to contain failed checks"
    assert all(f["check_id"] for f in findings)
