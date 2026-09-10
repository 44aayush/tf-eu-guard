"""Validate the Checkov runner (tf_eu_guard.checkov_runner).

``extract_failed_checks`` is tested hermetically against a sample payload. The
live ``run_checkov`` smoke test is opt-in (set ``TFEG_RUN_CHECKOV=1`` and have
the ``checkov`` CLI installed) so the default ``pytest`` run stays fast; the
consolidated ``tests/run_all_tests.sh`` enables it automatically when Checkov
is present.
"""

import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from tf_eu_guard.checkov_runner import (
    _normalize_checkov_output,
    extract_failed_checks,
    load_checkov_json,
    run_checkov,
)
from tf_eu_guard.constants import SUPPORTED_IAC_TYPES

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


def test_extract_empty_failed_checks_is_empty():
    """A well-formed Checkov result with zero failures is legitimately empty."""
    assert extract_failed_checks({"results": {"failed_checks": []}}) == []


def test_extract_missing_results_raises():
    """Non-Checkov input (e.g. a raw Terraform plan) must fail loudly, not
    silently return [] — that's the shape mismatch that shipped as a
    fake '0 findings' scan."""
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks({})


def test_extract_raw_terraform_plan_raises():
    """The exact shipped bug: a terraform show -json plan fed to
    extract_failed_checks must raise instead of returning []."""
    raw_plan = json.loads(
        (Path(__file__).parent / "fixtures" / ".." / ".."
         / "examples" / "vulnerable-aws-plan" / "plan.json").read_text()
    )
    assert "format_version" in raw_plan  # sanity: this IS a raw plan
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks(raw_plan)


def test_extract_results_wrong_type_raises():
    with pytest.raises(ValueError, match="does not look like Checkov output"):
        extract_failed_checks({"results": "not a dict"})


def test_extract_defaults_line_range_when_absent():
    payload = {"results": {"failed_checks": [{"check_id": "X"}]}}
    out = extract_failed_checks(payload)
    assert out[0]["check_id"] == "X"
    assert out[0]["file_line_range"] == [0, 0]


@pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or importlib.util.find_spec("checkov") is None,
    reason="live Checkov smoke test: set TFEG_RUN_CHECKOV=1 with Checkov installed in this Python environment",
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

K8S_ELEMENT = {
    "check_type": "kubernetes",
    "results": {"failed_checks": [{"check_id": "CKV_K8S_17"}]},
}

# A repo with both Terraform and Kubernetes files: Checkov returns one element
# per framework in a single JSON array.
MIXED_FRAMEWORKS = [
    SAMPLE,        # terraform
    K8S_ELEMENT,   # kubernetes
]


def test_normalize_dict_passthrough():
    assert _normalize_checkov_output(SAMPLE) is SAMPLE


def test_normalize_array_picks_terraform():
    picked = _normalize_checkov_output(MULTI_TYPE)
    assert picked["check_type"] == "terraform"
    assert [c["check_id"] for c in extract_failed_checks(picked)] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_normalize_array_picks_requested_iac_type():
    """Mixed terraform/kubernetes input selects the right element per request."""
    assert _normalize_checkov_output(MIXED_FRAMEWORKS, "terraform")["check_type"] == "terraform"
    assert _normalize_checkov_output(MIXED_FRAMEWORKS, "kubernetes")["check_type"] == "kubernetes"


def test_normalize_mixed_array_kubernetes_ids():
    picked = _normalize_checkov_output(MIXED_FRAMEWORKS, "kubernetes")
    assert [c["check_id"] for c in extract_failed_checks(picked)] == ["CKV_K8S_17"]


def test_normalize_defaults_to_terraform():
    """Without an explicit iac_type, terraform remains the default selection."""
    assert _normalize_checkov_output(MIXED_FRAMEWORKS)["check_type"] == "terraform"


def test_normalize_missing_requested_type_falls_back():
    """Requesting kubernetes in a terraform+secrets array falls back to an object."""
    picked = _normalize_checkov_output(MULTI_TYPE, "kubernetes")
    assert picked["check_type"] == "secrets"  # first usable element


def test_normalize_array_falls_back_to_first_object():
    data = [{"results": {"failed_checks": [{"check_id": "Z"}]}}]
    assert _normalize_checkov_output(data)["results"]["failed_checks"][0]["check_id"] == "Z"


def test_normalize_empty_array_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output([])


def test_normalize_bad_shape_raises():
    with pytest.raises(ValueError):
        _normalize_checkov_output("not a checkov object")


def test_load_checkov_json_threads_iac_type(tmp_path):
    p = tmp_path / "ckv-mixed.json"
    p.write_text(json.dumps(MIXED_FRAMEWORKS))
    out = extract_failed_checks(load_checkov_json(p, "kubernetes"))
    assert [c["check_id"] for c in out] == ["CKV_K8S_17"]


def test_run_checkov_rejects_unknown_iac_type(tmp_path):
    with pytest.raises(ValueError, match="Unsupported iac_type"):
        run_checkov(tmp_path, "bogus_framework")


def test_run_checkov_rejects_missing_target(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_checkov(tmp_path / "no-such-dir")


def test_run_checkov_plan_requires_file(tmp_path):
    """terraform_plan scans a plan FILE — a directory is a target mismatch."""
    with pytest.raises(ValueError, match="terraform_plan requires a plan file"):
        run_checkov(tmp_path, "terraform_plan")


def test_run_checkov_plan_builds_file_invocation(repo_root):
    """Plan mode must invoke checkov -f <plan.json> --framework terraform_plan."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        plan = repo_root / "examples" / "vulnerable-aws-plan" / "plan.json"
        if not plan.exists():
            pytest.skip("examples/vulnerable-aws-plan/plan.json not present")
        out = run_checkov(plan, "terraform_plan")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[cmd.index("-f") + 1] == str(plan)
    assert cmd[cmd.index("--framework") + 1] == "terraform_plan"
    assert "-d" not in cmd
    assert extract_failed_checks(out)[0]["check_id"] == "CKV_AWS_17"


def test_run_checkov_directory_uses_dash_d(tmp_path):
    """Non-plan scans keep the -d <directory> invocation."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        out = run_checkov(tmp_path, "terraform")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[cmd.index("-d") + 1] == str(tmp_path)
    assert "-f" not in cmd
    assert extract_failed_checks(out)[0]["check_id"] == "CKV_AWS_17"


def test_run_checkov_invokes_own_interpreter(tmp_path):
    """Checkov must run via this process's interpreter (``python -m
    checkov.main``), never a bare ``checkov`` resolved from PATH — a stray
    global install elsewhere on PATH could otherwise shadow the environment
    tf-eu-guard actually runs in, and a working feature would look broken
    (this happened). Note the module is ``checkov.main``: Checkov ships no
    package-level ``__main__.py``, so ``python -m checkov`` errors out.
    This pins the environment guarantee."""
    import sys as _sys

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        run_checkov(tmp_path, "terraform")
    finally:
        monkeypatch.undo()

    cmd = captured["cmd"]
    assert cmd[0] == _sys.executable
    assert cmd[1] == "-m"
    assert cmd[2] == "checkov.main"
    assert "checkov" != cmd[2]  # guard against reverting to the non-executable package


def test_supported_iac_types_contents():
    assert SUPPORTED_IAC_TYPES == (
        "terraform", "terraform_plan", "kubernetes",
    )


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
