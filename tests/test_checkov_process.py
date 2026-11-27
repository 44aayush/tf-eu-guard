"""Validate the Checkov runner (tf_eu_guard.checkov_runner).

``extract_failed_checks`` is tested hermetically against a sample payload. The
live ``run_checkov`` smoke test is opt-in (set ``TFEG_RUN_CHECKOV=1`` and have
the ``checkov`` CLI installed) so the default ``pytest`` run stays fast; the
consolidated ``tests/run_all_tests.sh`` enables it automatically when Checkov
is present.
"""

import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tf_eu_guard.checkov.process import (
    check_hcl2_module,
    hidden_dirs_warning,
    hidden_source_dirs,
)
from tf_eu_guard.checkov_runner import (
    CheckovRuntimeError,
    extract_failed_checks,
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


@pytest.mark.parametrize("returncode", [1, 2])
def test_run_checkov_invalid_json_is_runtime_failure(tmp_path, returncode):
    def fake_run(cmd, **kwargs):
        return type(
            "R",
            (),
            {
                "returncode": returncode,
                "stdout": "",
                "stderr": "traceback line\nfinal Checkov crash detail",
            },
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
        return type(
            "R",
            (),
            {
                "returncode": 2,
                "stdout": "{}",
                "stderr": "configuration error: bad fixture",
            },
        )()

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
        return type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(payload),
                "stderr": "",
            },
        )()

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
        return type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(payload),
                "stderr": "",
            },
        )()

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
    assert cmd[0] == sys.executable
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
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('shadowed')\n"
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
        "terraform",
        "terraform_plan",
        "kubernetes",
    )


def _fake_drive(monkeypatch, mapping):
    """Simulate Windows drives: *mapping* maps a path-string prefix to a drive."""

    def splitdrive(path):
        path = str(path)
        for prefix, drive in mapping.items():
            if path.startswith(prefix):
                return drive, path[len(prefix) :]
        return "", path

    monkeypatch.setattr("tf_eu_guard.checkov.process.os.path.splitdrive", splitdrive)


def test_trusted_workdir_keeps_default_on_same_drive(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    default = Path(process.sysconfig.get_path("purelib"))
    _fake_drive(monkeypatch, {str(default): "c:", str(tmp_path): "C:"})
    assert process.trusted_checkov_workdir(tmp_path) == default


def test_trusted_workdir_uses_target_drive_root_on_other_drive(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    default = Path(process.sysconfig.get_path("purelib"))
    _fake_drive(monkeypatch, {str(default): "C:", str(tmp_path): "D:"})
    workdir = process.trusted_checkov_workdir(tmp_path)
    assert workdir == Path("D:" + os.sep)
    assert not str(workdir).startswith(str(tmp_path))


def test_run_checkov_passes_target_to_workdir(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    seen = {}
    monkeypatch.setattr(
        process, "trusted_checkov_workdir", lambda t: seen.setdefault("t", t) and tmp_path
    )
    monkeypatch.setattr(
        process.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")),
    )
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    with pytest.raises(RuntimeError, match="stop"):
        process.run_checkov(plan, "terraform_plan")
    assert seen["t"] == plan.resolve()


# --- T-09..T-12: network, scrubbed environment, guards, excludes, modules -----


def _capture_cmd(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        return type("R", (), {"returncode": 0, "stdout": json.dumps(SAMPLE), "stderr": ""})()

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    return captured


def _tf_dir(tmp_path, body='resource "aws_s3_bucket" "b" {}\n'):
    (tmp_path / "main.tf").write_text(body)
    return tmp_path


def test_skip_download_is_default_and_online_omits_it(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    run_checkov(_tf_dir(tmp_path))
    assert "--skip-download" in captured["cmd"]
    run_checkov(tmp_path, online=True)
    assert "--skip-download" not in captured["cmd"]


def test_platform_and_ignore_variables_are_scrubbed_even_online(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    for name in (
        "BC_API_KEY",
        "PRISMA_API_URL",
        "BC_CA_BUNDLE",
        "CKV_IGNORED_DIRECTORIES",
        "CKV_IGNORE_HIDDEN_DIRECTORIES",
    ):
        monkeypatch.setenv(name, "x")
    monkeypatch.setenv("UNRELATED_VAR", "dropped")
    monkeypatch.setenv("LANG", "C.UTF-8")
    run_checkov(_tf_dir(tmp_path), online=True)
    env = captured["env"]
    for name in (
        "BC_API_KEY",
        "PRISMA_API_URL",
        "BC_CA_BUNDLE",
        "CKV_IGNORED_DIRECTORIES",
        "CKV_IGNORE_HIDDEN_DIRECTORIES",
    ):
        assert name not in env
    assert "UNRELATED_VAR" not in env
    assert env["LANG"] == "C.UTF-8"


def test_exclude_is_passed_to_checkov_as_skip_path(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    run_checkov(_tf_dir(tmp_path), exclude=("tests/fixtures", r"vendor/.*\.tf$"))
    cmd = captured["cmd"]
    pairs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--skip-path"]
    assert pairs == ["tests/fixtures", r"vendor/.*\.tf$"]


def test_guards_skip_hidden_terraform_and_node_modules(tmp_path, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-outside.txt")
    outside.write_text("x")
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(outside)
    cache = tmp_path / ".terraform" / "modules" / "x"
    cache.mkdir(parents=True)
    (cache / "versions.tf.json").write_text("{}")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "a.tf.json").write_text("{}")
    assert run_checkov(tmp_path)["results"]["failed_checks"]


def test_escaping_tf_symlink_still_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.tf"
    outside.write_text("")
    (root / "link.tf").symlink_to(outside)
    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(root)


def test_broken_tf_symlink_rejected_but_other_broken_link_only_warns(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    (tmp_path / "gone.txt").symlink_to(tmp_path / "missing")
    run_checkov(tmp_path)
    assert "broken symlink" in capsys.readouterr().err
    (tmp_path / "gone.tf").symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="broken"):
        run_checkov(tmp_path)


def test_escaping_non_source_symlink_warns_but_escaping_dir_rejected(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    root = tmp_path / "root"
    root.mkdir()
    _tf_dir(root)
    outside = tmp_path / "outside.bin"
    outside.write_text("x")
    (root / "data.bin").symlink_to(outside)
    run_checkov(root)
    assert "resolves outside scan root" in capsys.readouterr().err
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    (root / "linkdir").symlink_to(outdir)
    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(root)


def test_kubernetes_symlink_suffixes_follow_framework(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "o.yaml"
    outside.write_text("")
    (root / "link.yaml").symlink_to(outside)
    with pytest.raises(ValueError, match="resolves outside scan root"):
        run_checkov(root, "kubernetes")


def test_exclude_honoured_by_guards(tmp_path, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    broken = tmp_path / "fixtures"
    broken.mkdir()
    (broken / "bad.tf.json").write_text("{}")
    (broken / "bad.tf").symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError):
        run_checkov(tmp_path)
    assert run_checkov(tmp_path, exclude=("fixtures",))["results"]["failed_checks"]
    # regex semantics, as Checkov's --skip-path
    assert run_checkov(tmp_path, exclude=(r"fix.ures$",))["results"]["failed_checks"]


def test_remote_module_warning(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    (tmp_path / "main.tf").write_text(
        'module "reg" {\n  source = "terraform-aws-modules/s3-bucket/aws"\n}\n'
        'module "git" {\n  source = "git::https://example.com/x.git?ref=v1"\n}\n'
        'module "loc" {\n  source = "./modules/local"\n}\n'
        'module "up" {\n  source = "../shared"\n}\n'
    )
    run_checkov(tmp_path)
    err = capsys.readouterr().err
    assert "not analysed: remote module sources" in err
    assert "module.reg (terraform-aws-modules/s3-bucket/aws)" in err
    assert "module.git (git::https://example.com/x.git?ref=v1)" in err
    assert "module.loc" not in err
    assert "module.up" not in err


def test_no_remote_module_warning_for_local_only(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path, 'module "loc" {\n  source = "./m"\n}\n')
    run_checkov(tmp_path)
    assert "remote module" not in capsys.readouterr().err


def test_cli_wires_exclude_and_online(monkeypatch, tmp_path):
    from tf_eu_guard.cli.parser import build_parser

    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--exclude", "a", "--skip-path", "b", "--online"]
    )
    assert args.exclude == ["a", "b"]
    assert args.online is True
    assert build_parser().parse_args(["scan", "."]).online is False


@pytest.mark.parametrize("output", ["dev", "security", "auditor", "json", "sarif", "all"])
def test_reporters_tolerate_missing_guideline(repo_root, tmp_path, monkeypatch, output):
    from tests.cli_helpers import run_cli

    fixture = json.loads((repo_root / "tests/fixtures/checkov-vulnerable-tf.json").read_text())
    assert fixture["results"]["failed_checks"]
    for check in fixture["results"]["failed_checks"]:
        check["guideline"] = None
    source = tmp_path / "in.json"
    source.write_text(json.dumps(fixture))
    code = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(source),
        "--output",
        output,
        "--output-dir",
        str(tmp_path / "out"),
    )
    assert code in (0, 1, None)


def _ok_result():
    return type(
        "R",
        (),
        {
            "returncode": 0,
            "stdout": '{"results": {"failed_checks": []}, "summary": {"parsing_errors": 0}}',
            "stderr": "",
        },
    )()


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [({}, 600), ({"timeout": 12.5}, 12.5), ({"timeout": 0}, None)],
)
def test_run_checkov_passes_timeout_and_encoding(tmp_path, monkeypatch, kwargs, expected):
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw)
        return _ok_result()

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
    run_checkov(tmp_path, **kwargs)
    assert seen["timeout"] == expected
    assert seen["encoding"] == "utf-8"
    assert seen["errors"] == "replace"
    assert "text" not in seen


def test_run_checkov_timeout_raises_runtime_error(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {}\n')
    with pytest.raises(CheckovRuntimeError, match="did not finish within 5 seconds"):
        run_checkov(tmp_path, timeout=5)


def test_var_files_passed_to_checkov(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    (tmp_path / "a.tfvars").write_text("x = 1\n")
    (tmp_path / "b.tfvars").write_text("y = 2\n")
    run_checkov(tmp_path, var_files=[tmp_path / "a.tfvars", tmp_path / "b.tfvars"])
    cmd = captured["cmd"]
    pairs = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--var-file"]
    assert pairs == [str((tmp_path / "a.tfvars").resolve()), str((tmp_path / "b.tfvars").resolve())]


def test_download_external_modules_flag(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    run_checkov(tmp_path, download_external_modules=True)
    cmd = captured["cmd"]
    assert cmd[cmd.index("--download-external-modules") + 1] == "true"
    run_checkov(tmp_path)
    assert "--download-external-modules" not in captured["cmd"]


def test_remote_module_warning_suppressed_when_downloading(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path, 'module "reg" {\n  source = "terraform-aws-modules/s3-bucket/aws"\n}\n')
    run_checkov(tmp_path, download_external_modules=True)
    err = capsys.readouterr().err
    assert "not analysed" not in err
    assert "third-party module code" in err


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_var_file_missing_or_directory_rejected(tmp_path, monkeypatch, kind):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path)
    bad = tmp_path / "nope.tfvars"
    if kind == "directory":
        bad.mkdir()
    with pytest.raises(ValueError, match="var file"):
        run_checkov(tmp_path, var_files=[bad])


def test_var_file_missing_exits_2(monkeypatch, tmp_path, capsys):
    from tests.cli_helpers import run_cli

    _tf_dir(tmp_path)
    rc = run_cli(monkeypatch, tmp_path, str(tmp_path), "--var-file", "nope.tfvars")
    assert rc == 2
    assert "var file" in capsys.readouterr().err


@pytest.mark.parametrize("flag", [["--var-file", "x.tfvars"], ["--download-external-modules"]])
@pytest.mark.parametrize(
    "extra",
    [["--iac-type", "kubernetes"], ["--checkov-json", "tests/fixtures/checkov-vulnerable-tf.json"]],
)
def test_terraform_only_flags_rejected(monkeypatch, tmp_path, capsys, repo_root, flag, extra):
    from tests.cli_helpers import run_cli

    (tmp_path / "x.tfvars").write_text("")
    extra = [str(repo_root / e) if e.endswith(".json") else e for e in extra]
    assert run_cli(monkeypatch, tmp_path, str(tmp_path), *extra, *flag) == 2
    assert "only valid with --iac-type terraform" in capsys.readouterr().err


def test_tfvars_region_resolved_end_to_end(monkeypatch, tmp_path, repo_root, capsys):
    pytest.importorskip("checkov")
    from tests.cli_helpers import run_cli

    fixture = repo_root / "tests/fixtures/var-file-region"

    def policy_hits(*extra):
        assert run_cli(monkeypatch, tmp_path, str(fixture), "--output", "json", *extra) == 0
        return [
            f for f in json.loads(capsys.readouterr().out) if f["check_id"] == "EUGUARD_POLICY_001"
        ]

    assert policy_hits()
    assert not policy_hits("--var-file", str(fixture / "prod.tfvars"))


def test_log_level_never_reaches_checkov(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    assert "LOG_LEVEL" not in checkov_environment()


def test_checkov_environment_drops_git_variables(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    assert "GIT_DIR" not in checkov_environment()


def test_checkov_environment_drops_unknown_variables(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    for name in ("CHECKOV_CREATE_GRAPH", "CKV_FRAMEWORK", "BC_API_KEY", "GIT_DIR", "FOO"):
        monkeypatch.setenv(name, "x")
    env = checkov_environment()
    assert not {"CHECKOV_CREATE_GRAPH", "CKV_FRAMEWORK", "BC_API_KEY", "GIT_DIR", "FOO"} & set(env)


def test_checkov_environment_keeps_proxy_and_locale(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    kept = {
        "HTTPS_PROXY": "http://p:3128",
        "no_proxy": "localhost",
        "REQUESTS_CA_BUNDLE": "/ca.pem",
        "SSL_CERT_FILE": "/ca.pem",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_CTYPE": "C.UTF-8",
        "TZ": "UTC",
        "XDG_CACHE_HOME": "/cache",
    }
    for name, value in kept.items():
        monkeypatch.setenv(name, value)
    env = checkov_environment()
    assert {k: env.get(k) for k in kept} == kept


def test_checkov_environment_keeps_windows_essentials(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    essentials = (
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "TEMP",
        "TMP",
    )
    for name in essentials:
        monkeypatch.setenv(name, "C:\\x")
    env = checkov_environment()
    assert all(env.get(name) == "C:\\x" for name in essentials)


def test_checkov_environment_keeps_module_restrictions(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    monkeypatch.setenv("CHECKOV_TERRAFORM_ALLOWED_MODULE_PREFIXES", "git::https://corp/")
    monkeypatch.setenv("VCS_ALLOWED_HOSTS", "corp")
    env = checkov_environment(allow_module_download=False)
    assert env["CHECKOV_TERRAFORM_ALLOWED_MODULE_PREFIXES"] == "git::https://corp/"
    assert env["VCS_ALLOWED_HOSTS"] == "corp"


def test_checkov_environment_module_credentials_only_when_downloading(monkeypatch):
    from tf_eu_guard.checkov.process import CHECKOV_MODULE_DOWNLOAD_ENV, checkov_environment

    for name in CHECKOV_MODULE_DOWNLOAD_ENV:
        monkeypatch.setenv(name, "secret")
    assert not CHECKOV_MODULE_DOWNLOAD_ENV & set(checkov_environment())
    env = checkov_environment(allow_module_download=True)
    assert CHECKOV_MODULE_DOWNLOAD_ENV <= set(env)


def test_run_checkov_passes_allow_module_download(tmp_path, monkeypatch):
    captured = _capture_cmd(monkeypatch)
    monkeypatch.setenv("GITHUB_PAT", "secret")
    run_checkov(_tf_dir(tmp_path))
    assert "GITHUB_PAT" not in captured["env"]
    run_checkov(tmp_path, download_external_modules=True)
    assert captured["env"]["GITHUB_PAT"] == "secret"


def test_checkov_environment_windows_matches_case_insensitively(monkeypatch):
    from tf_eu_guard.checkov import process

    monkeypatch.setattr(process.sys, "platform", "win32")
    monkeypatch.setattr(
        process.os, "environ", {"SystemRoot": "C:\\Windows", "lc_all": "C", "Foo": "x"}
    )
    env = process.checkov_environment()
    assert env == {"SystemRoot": "C:\\Windows", "lc_all": "C"}


def test_checkov_env_allowlist_is_exact():
    from tf_eu_guard.checkov.process import CHECKOV_ENV_ALLOWLIST

    assert CHECKOV_ENV_ALLOWLIST == {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TEMP", "TMP",
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA",
        "LOCALAPPDATA", "PROGRAMDATA", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy",
        "https_proxy", "no_proxy", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "CURL_CA_BUNDLE", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
        "CHECKOV_TERRAFORM_ALLOWED_MODULE_PREFIXES", "VCS_ALLOWED_HOSTS",
    }  # fmt: skip


def test_checkov_environment_applies_extra(monkeypatch):
    from tf_eu_guard.checkov.process import checkov_environment

    monkeypatch.setenv("FOO", "ambient")
    env = checkov_environment({"TF_EU_GUARD_X": "1", "PATH": "/override"})
    assert env["TF_EU_GUARD_X"] == "1"
    assert env["PATH"] == "/override"
    assert "FOO" not in env


def _hidden_tree(tmp_path):
    (tmp_path / "main.tf").write_text("# root\n")
    (tmp_path / ".prod" / "env").mkdir(parents=True)
    (tmp_path / ".prod" / "env" / "main.tf").write_text("# prod\n")
    return tmp_path


def test_hidden_source_dirs_finds_dot_prod(tmp_path):
    root = _hidden_tree(tmp_path)
    found = hidden_source_dirs(root, "terraform")
    assert found == [root / ".prod"]
    warning = hidden_dirs_warning(found, "terraform")
    assert "1 hidden directory contains .tf, .tfvars, .hcl files" in warning
    assert str(root / ".prod") in warning


def test_hidden_dir_warning_ignores_tooling_dirs(tmp_path):
    for name in (".git", ".github", ".terraform", ".venv", ".tox", ".cache"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.tf").write_text("# x\n")
    (tmp_path / ".empty").mkdir()
    (tmp_path / ".docs").mkdir()
    (tmp_path / ".docs" / "readme.md").write_text("x\n")
    assert hidden_source_dirs(tmp_path, "terraform") == []


def test_hidden_source_dirs_honours_exclude(tmp_path):
    root = _hidden_tree(tmp_path)
    assert hidden_source_dirs(root, "terraform", [".prod"]) == []


def test_hidden_source_dirs_kubernetes_yaml(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / ".overlays").mkdir()
    (tmp_path / "app" / ".overlays" / "deploy.yaml").write_text("kind: Pod\n")
    assert hidden_source_dirs(tmp_path, "kubernetes") == [tmp_path / "app" / ".overlays"]
    assert hidden_source_dirs(tmp_path, "terraform") == []
    assert "directories contain" in hidden_dirs_warning([Path("a"), Path("b")], "kubernetes")


def test_hidden_dir_warning_ignores_editor_dirs(tmp_path):
    for name, config in (
        (".vscode", "settings.json"),
        (".devcontainer", "devcontainer.json"),
        (".idea", "x.json"),
    ):
        (tmp_path / name).mkdir()
        (tmp_path / name / config).write_text("{}")
    assert hidden_source_dirs(tmp_path, "kubernetes") == []


def test_hidden_dir_with_only_plugin_cache_is_ignored(tmp_path):
    module = tmp_path / ".prod" / ".terraform" / "modules" / "x"
    module.mkdir(parents=True)
    (module / "main.tf").write_text("# cached\n")
    assert hidden_source_dirs(tmp_path, "terraform") == []


def test_hidden_source_dirs_does_not_follow_symlinked_hidden_dir(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf").write_text("# elsewhere\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "main.tf").write_text("# root\n")
    (root / ".ext").symlink_to(Path("..") / "outside", target_is_directory=True)
    assert hidden_source_dirs(root, "terraform") == []


@pytest.mark.parametrize(
    "name", [".terragrunt-cache", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".circleci"]
)
def test_hidden_dir_warning_ignores_more_tooling_dirs(tmp_path, name):
    (tmp_path / name).mkdir()
    (tmp_path / name / "x.tf").write_text("# x\n")
    (tmp_path / name / "k.yaml").write_text("kind: Pod\n")
    assert hidden_source_dirs(tmp_path, "terraform") == []
    assert hidden_source_dirs(tmp_path, "kubernetes") == []


def test_hidden_source_dirs_exclude_applies_to_the_inner_walk(tmp_path):
    (tmp_path / ".prod" / "vendor").mkdir(parents=True)
    (tmp_path / ".prod" / "vendor" / "main.tf").write_text("# vendored\n")
    assert hidden_source_dirs(tmp_path, "terraform") == [tmp_path / ".prod"]
    assert hidden_source_dirs(tmp_path, "terraform", ["vendor"]) == []


def test_run_checkov_prints_hidden_dir_warning(tmp_path, capsys, monkeypatch):
    _capture_cmd(monkeypatch)
    _tf_dir(tmp_path, "# root\n")
    (tmp_path / ".prod").mkdir()
    (tmp_path / ".prod" / "main.tf").write_text("# prod\n")
    run_checkov(tmp_path)
    err = capsys.readouterr().err
    assert "not scanned: 1 hidden directory contains" in err
    assert str(tmp_path.resolve() / ".prod") in err


def test_hcl2_self_check_passes_with_bc_fork():
    check_hcl2_module()


def test_hcl2_self_check_rejects_foreign_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "hcl2", types.ModuleType("hcl2"))
    with pytest.raises(CheckovRuntimeError, match="bc-python-hcl2"):
        check_hcl2_module()


def test_run_checkov_reports_foreign_hcl2_before_running(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "hcl2", types.ModuleType("hcl2"))
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    with pytest.raises(CheckovRuntimeError, match="uv tool install tf-eu-guard"):
        run_checkov(tmp_path, "terraform")
    assert calls == []
