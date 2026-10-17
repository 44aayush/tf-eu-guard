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
    CheckovRuntimeError,
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
    "summary": {"parsing_errors": 0},
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
    payload = {"results": {"failed_checks": [check]}}

    with pytest.raises(ValueError, match=message):
        extract_failed_checks(payload)


@pytest.mark.parametrize("field", ["check_id", "check_name", "resource", "file_path", "file_line_range"])
def test_extract_rejects_missing_required_finding_fields(field):
    check = dict(SAMPLE["results"]["failed_checks"][0])
    del check[field]

    with pytest.raises(ValueError, match=f"missing required field.*{field}"):
        extract_failed_checks({"results": {"failed_checks": [check]}})


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
    "results": {"failed_checks": [{
        "check_id": "CKV_K8S_17",
        "check_name": "Kubernetes check",
        "resource": "Pod/example",
        "file_path": "/pod.yaml",
        "file_line_range": [1, 2],
    }]},
}

# A repo with both Terraform and Kubernetes files: Checkov returns one element
# per framework in a single JSON array.
MIXED_FRAMEWORKS = [
    SAMPLE,        # terraform
    K8S_ELEMENT,   # kubernetes
]


def test_normalize_dict_passthrough():
    assert _normalize_checkov_output(SAMPLE) is SAMPLE


def test_normalize_legacy_single_object_without_type_is_supported():
    """Legacy single-object captures may omit check_type for compatibility."""
    legacy = {"results": {"failed_checks": [{"check_id": "LEGACY"}]}}
    assert _normalize_checkov_output(legacy, "terraform") is legacy


def test_normalize_single_object_rejects_wrong_type():
    with pytest.raises(ValueError, match="declares check_type.*kubernetes"):
        _normalize_checkov_output(K8S_ELEMENT, "terraform")


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


def test_normalize_missing_requested_type_raises():
    """A typed array must not fall back to a result from another framework."""
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
    p = tmp_path / "ckv-mixed.json"
    p.write_text(json.dumps(MIXED_FRAMEWORKS))
    out = extract_failed_checks(load_checkov_json(p, "kubernetes"))
    assert [c["check_id"] for c in out] == ["CKV_K8S_17"]


@pytest.mark.parametrize("returncode", [1, 2])
def test_run_checkov_invalid_json_is_runtime_failure(tmp_path, returncode):
    def fake_run(cmd, **kwargs):
        return type(
            "R", (), {
                "returncode": returncode,
                "stdout": "",
                "stderr": "traceback line\nfinal Checkov crash detail",
            }
        )()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match="final Checkov crash detail"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_nonzero_status_includes_stderr(tmp_path):
    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 2,
            "stdout": "{}",
            "stderr": "configuration error: bad fixture",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match="configuration error: bad fixture"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_parsing_errors_and_names_files(tmp_path):
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [],
            "parsing_errors": ["broken.tf"],
        },
        "summary": {"parsing_errors": 1},
    }

    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
        with pytest.raises(CheckovRuntimeError, match=r"parsing error.*broken\.tf"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_summary_only_empty_source_scan(tmp_path):
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
    }

    def fake_run(cmd, **kwargs):
        return type("R", (), {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        })()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    try:
        with pytest.raises(CheckovRuntimeError, match="no terraform scan results"):
            run_checkov(tmp_path)
    finally:
        monkeypatch.undo()


def test_run_checkov_rejects_tf_json_source(tmp_path):
    (tmp_path / "main.tf.json").write_text("{}\n")
    with pytest.raises(ValueError, match=r"\.tf\.json"):
        run_checkov(tmp_path)


def test_run_checkov_rejects_symlink_outside_scan_root(repo_root):
    target = repo_root / "tests" / "fixtures" / "symlink-outside"

    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(target)


def test_run_checkov_rejects_symlink_directory_outside_scan_root(repo_root):
    target = repo_root / "tests" / "fixtures" / "symlink-outside-dir"

    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(target)


def test_run_checkov_allows_in_root_symlinks(repo_root, monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    target = repo_root / "tests" / "fixtures" / "symlink-in-root"

    output = run_checkov(target)

    assert output["results"]["failed_checks"]
    assert captured["cmd"][captured["cmd"].index("-d") + 1] == str(target.resolve())


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
        plan_output = {**SAMPLE, "check_type": "terraform_plan"}
        return type("R", (), {"returncode": 0, "stdout": json.dumps(plan_output), "stderr": ""})()

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
    """Checkov runs in isolated mode through this process's interpreter."""
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
    assert cmd[1] == "-I"
    assert cmd[2] == "-c"
    assert "checkov.main" in cmd[3]


def test_run_checkov_does_not_forward_checkov_skip_environment(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch.setenv("CKV_SKIP_CHECK", "CKV_AWS_18")
    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')

    run_checkov(tmp_path, "terraform")

    assert captured["env"]["PATH"]
    assert "CKV_SKIP_CHECK" not in captured["env"]
    assert captured["cwd"] != tmp_path


@pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="Checkov is not installed",
)
def test_run_checkov_checkout_cannot_shadow_checkov(tmp_path):
    """A package under the scanned directory is not importable by Checkov."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    sentinel = tmp_path / "shadowed"
    fake_checkov = target / "checkov"
    fake_checkov.mkdir()
    (fake_checkov / "__init__.py").write_text("")
    (fake_checkov / "main.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('shadowed')\n"
    )

    output = run_checkov(target)
    assert output["check_type"] == "terraform"
    assert not sentinel.exists()


@pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="Checkov is not installed",
)
def test_run_checkov_ignores_checkout_checkov_config(tmp_path):
    """A checkout .checkov.yml cannot suppress wrapper-required checks."""
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    (tmp_path / ".checkov.yml").write_text("skip-check: CKV_AWS_18\n")

    output = run_checkov(tmp_path)
    assert any(check["check_id"] == "CKV_AWS_18" for check in output["results"]["failed_checks"])


def test_supported_iac_types_contents():
    assert SUPPORTED_IAC_TYPES == (
        "terraform", "terraform_plan", "kubernetes",
    )


def test_load_checkov_json_from_file(tmp_path):
    p = tmp_path / "ckv.json"
    p.write_text(json.dumps(SAMPLE))
    out = extract_failed_checks(load_checkov_json(p))
    assert [c["check_id"] for c in out] == ["CKV_AWS_17", "CKV_AWS_20"]


def test_load_checkov_json_rejects_directory(tmp_path):
    from tf_eu_guard.checkov_runner import CheckovInputError

    with pytest.raises(CheckovInputError, match="must be a file"):
        load_checkov_json(tmp_path)


def test_load_checkov_json_permission_error_is_user_input(monkeypatch, tmp_path):
    from tf_eu_guard.checkov_runner import CheckovInputError

    p = tmp_path / "ckv.json"
    p.write_text("{}")
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: (_ for _ in ()).throw(
        PermissionError(13, "Permission denied")
    ))
    with pytest.raises(CheckovInputError, match="Cannot read Checkov JSON input"):
        load_checkov_json(p)


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
