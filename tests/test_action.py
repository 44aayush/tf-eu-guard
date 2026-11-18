"""Static and shell-level checks for the composite GitHub Action."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ACTION = Path(__file__).parents[1] / "action.yml"
ACTION_E2E = Path(__file__).parents[1] / ".github" / "workflows" / "action-e2e.yml"


def test_action_inputs_are_passed_through_env_not_shell_code():
    text = ACTION.read_text(encoding="utf-8")
    run = text.split("      run: |", 1)[1].split("\n\n    - name:", 1)[0]
    assert "${{ inputs." not in run
    for variable in (
        "INPUT_PATH",
        "INPUT_IAC_TYPE",
        "INPUT_OUTPUT",
        "INPUT_FRAMEWORK",
        "INPUT_FAIL_ON_SEVERITY",
        "INPUT_FAIL_ON_ANY",
        "INPUT_FAIL_ON_SUPPRESSED",
        "INPUT_RESIDENCY_POLICY",
        "INPUT_ALLOWED_REGIONS",
        "INPUT_CHECKOV_JSON",
        "INPUT_OUTPUT_DIR",
        "INPUT_OUTPUT_FILE",
        "INPUT_TIMEOUT",
    ):
        assert f'"${variable}"' in run


def _find_bash() -> str | None:
    """Return a usable bash, rejecting the WSL launcher on Windows."""
    if sys.platform != "win32":
        return shutil.which("bash")
    candidates = []
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    for root in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432")):
        if root:
            candidates.append(str(Path(root) / "Git" / "bin" / "bash.exe"))
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve() / "System32"
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and path.resolve().parent != system32:
            return str(path)
    return None


def test_action_argument_array_preserves_hostile_input_literally(tmp_path):
    bash = _find_bash()
    if bash is None:
        pytest.skip("Git Bash not found (System32\\bash.exe is the WSL launcher and is not used)")
    sentinel = tmp_path / "injection"
    hostile = f'a"; touch {sentinel}; $(printf pwned) whitespace'
    script = 'args=(); args+=("$INPUT_PATH"); printf "%s\\n" "${args[0]}"'
    result = subprocess.run(
        [bash, "-c", script],
        env={"INPUT_PATH": hostile},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.rstrip("\n") == hostile
    assert not sentinel.exists()


def test_html_artifact_upload_is_limited_to_html_outputs_and_effective_directory():
    text = ACTION.read_text(encoding="utf-8")
    assert (
        "steps.scan.outputs.upload-reports == 'true' && "
        "(inputs.output == 'all' || ((inputs.output == 'security' || "
        "inputs.output == 'auditor') && inputs.output-file == ''))"
    ) in text
    assert "path: ${{ inputs.output-dir || 'reports' }}/*.html" in text
    assert "inputs.output-file != ''" in text
    assert "path: ${{ inputs.output-file }}" in text
    assert "if-no-files-found: error" in text
    assert text.count("name: ${{ inputs.artifact-name }}") == 2
    assert "name: tf-eu-guard-reports" not in text


def test_sarif_upload_uses_effective_output_file():
    text = ACTION.read_text(encoding="utf-8")
    assert "sarif_file: ${{ inputs.output-file || 'tf-eu-guard.sarif' }}" in text
    assert "category: ${{ inputs.category }}" in text


def test_action_e2e_covers_upload_report_regressions():
    text = ACTION_E2E.read_text(encoding="utf-8")
    sarif_case = text.split("- name: Scan vulnerable Terraform fixture", 1)[1].split(
        "- name: Assert specific check IDs", 1
    )[0]
    assert "output: sarif" in sarif_case
    assert "upload-reports: true" in sarif_case
    assert "output-dir: action-artifacts" in text
    assert "output-file: action-artifacts/custom-result.sarif" in text
    assert "category: e2e-terraform-source" in text
    assert "category: e2e-terraform-custom" in text


def test_action_e2e_covers_custom_single_html_destination():
    text = ACTION_E2E.read_text(encoding="utf-8")
    assert "output: security" in text
    assert "output-file: action-artifacts/custom-security.html" in text
    assert "test -f action-artifacts/custom-security.html" in text


def test_action_exposes_fail_on_suppressed_and_residency_inputs():
    text = ACTION.read_text(encoding="utf-8")
    inputs = yaml.safe_load(text)["inputs"]
    assert inputs["fail-on-suppressed"]["default"] == "false"
    assert inputs["residency-policy"]["default"] == "eu-eea"
    assert inputs["allowed-regions"]["default"] == ""
    assert "INPUT_FAIL_ON_SUPPRESSED: ${{ inputs.fail-on-suppressed }}" in text
    assert "args+=(--fail-on-suppressed)" in text
    assert 'args+=(--residency-policy "$INPUT_RESIDENCY_POLICY")' in text
    assert 'args+=(--allowed-regions "$INPUT_ALLOWED_REGIONS")' in text


def _inputs() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["inputs"]


def _scan_run() -> str:
    steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "scan")


def test_artifact_name_input_defaults_to_the_previous_name():
    assert _inputs()["artifact-name"]["default"] == "tf-eu-guard-reports"


def test_default_output_is_dev_because_sarif_is_not_uploaded_by_default():
    inputs = _inputs()
    assert inputs["upload-sarif"]["default"] == "false"
    assert inputs["output"]["default"] == "dev"


def test_path_is_optional_because_it_has_a_default():
    path = _inputs()["path"]
    assert path["required"] is False
    assert path["default"] == "./terraform"


def test_linux_docker_requirement_is_documented():
    description = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["description"]
    assert "Linux runner with Docker" in description
    assert "Linux runner with Docker" in (ACTION.parent / "README.md").read_text(encoding="utf-8")


def test_timeout_input_is_forwarded_to_the_cli_flag():
    assert _inputs()["timeout"]["default"] == ""
    run = _scan_run()
    assert "INPUT_TIMEOUT: ${{ inputs.timeout }}" in ACTION.read_text(encoding="utf-8")
    assert 'args+=(--timeout "$INPUT_TIMEOUT")' in run


def test_workspace_is_mounted_at_its_host_path_and_description_has_no_container_path():
    run = _scan_run()
    assert '-v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro"' in run
    assert '-w "$GITHUB_WORKSPACE"' in run
    for name, spec in _inputs().items():
        assert "/workspace" not in spec["description"], name


def test_upload_conditions_use_normalised_boolean_outputs():
    text = ACTION.read_text(encoding="utf-8")
    assert "inputs.upload-reports ==" not in text
    assert "inputs.upload-sarif ==" not in text
    assert "steps.scan.outputs.upload-sarif == 'true'" in text
    run = _scan_run()
    # Uploads start disabled; the real values are written only after the
    # upload-target check passes.
    assert run.index('echo "upload-reports=false"') < run.index("docker run")
    assert run.index('echo "upload-sarif=false"') < run.index("docker run")
    assert run.rindex('echo "upload-reports=$upload_reports"') > run.index("docker run")
    assert run.rindex('echo "upload-sarif=$upload_sarif"') > run.index("docker run")


def _shell_helpers() -> str:
    """The is_true and out_rel functions, extracted verbatim from the Action."""
    run = _scan_run()
    is_true = run[run.index("is_true() {") : run.index("# Normalised values")]
    out_rel = run[run.index("out_rel() {") : run.index("args=()")]
    return is_true + out_rel


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", 0),
        ("True", 0),
        ("TRUE", 0),
        ("1", 0),
        ("yes", 0),
        ("YES", 0),
        ("false", 1),
        ("False", 1),
        ("0", 1),
        ("no", 1),
        ("", 1),
        ("truee", 1),
    ],
)
def test_boolean_inputs_are_normalised_case_insensitively(value, expected):
    bash = _find_bash()
    if bash is None:
        pytest.skip("bash not available")
    script = _shell_helpers() + '\nif is_true "$VALUE"; then exit 0; else exit 1; fi'
    result = subprocess.run([bash, "-c", script], env={"VALUE": value}, capture_output=True)
    assert result.returncode == expected, result.stderr


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("reports", "/out/reports"),
        ("./reports/x.sarif", "/out/reports/x.sarif"),
        ("/workspace/tf-eu-guard.sarif", "/out/tf-eu-guard.sarif"),
        ("/home/runner/work/r/r/out/a.sarif", "/out/out/a.sarif"),
        ("/etc/passwd", None),
        ("../escape", None),
        ("/home/runner/work/r/r/../x", None),
        ("a/../b", None),
    ],
)
def test_output_paths_accept_workspace_relative_and_absolute_workspace_paths(value, expected):
    bash = _find_bash()
    if bash is None:
        pytest.skip("bash not available")
    script = _shell_helpers() + '\nout_rel "$VALUE"'
    result = subprocess.run(
        [bash, "-c", script],
        env={"VALUE": value, "GITHUB_WORKSPACE": "/home/runner/work/r/r"},
        capture_output=True,
        text=True,
    )
    if expected is None:
        assert result.returncode == 2
        assert "::error::" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout == expected


def test_readme_documents_the_new_inputs_and_requirements():
    readme = (ACTION.parent / "README.md").read_text(encoding="utf-8")
    assert "`artifact-name`" in readme
    assert "`timeout`" in readme
    assert "| `output` | `--output` | `dev` |" in readme


BASH4_ONLY_PATTERNS = {
    "case-modification expansion ${x,,} ${x^^} ${x,} ${x^}": r"\$\{[A-Za-z_][A-Za-z_0-9]*(,,?|\^\^?)[^}]*\}|\$\{[1-9,^]*(,,?|\^\^?)\}",
    "declare -A / local -A (associative arrays)": r"\b(declare|local|typeset)\s+-[a-zA-Z]*A",
    "mapfile / readarray": r"\b(mapfile|readarray)\b",
    "|& pipe": r"\|&",
    "&>> redirect": r"&>>",
    "coproc": r"\bcoproc\b",
    "${x@Q} transform": r"\$\{[^}]*@[QEPAaUuL]\}",
    "negative array index": r"\$\{[A-Za-z_][A-Za-z_0-9]*\[-[0-9]+\]\}",
}


def test_action_script_avoids_bash4_only_constructs():
    run = _scan_run()
    found = [name for name, pat in BASH4_ONLY_PATTERNS.items() if re.search(pat, run)]
    assert not found, (
        "macOS ships bash 3.2 as /bin/bash, so the Action's shell must avoid bash 4+ "
        f"constructs; found: {found}"
    )


COUNT_NAMES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unmapped",
    "suppressed",
    "waived",
    "baselined",
    "total",
)

STUB_DOCKER = r"""#!/bin/sh
case "$1" in
  run)
    printf '%s\n' "$@" > "$STUB_LOG"
    for a in "$@"; do
      case "$a" in
        *:/out) out="${a%:/out}" ;;
      esac
    done
    if [ -z "$STUB_NO_FILES" ]; then
      mkdir -p "$out/.tf-eu-guard"
      printf '# tf-eu-guard summary\n' > "$out/.tf-eu-guard/summary.md"
      if [ -n "$STUB_SYMLINK" ]; then
        rm -f "$out/.tf-eu-guard/summary.md"
        ln -s "$STUB_SYMLINK" "$out/.tf-eu-guard/summary.md"
        mkdir -p "$out/reports"; ln -s "$STUB_SYMLINK" "$out/reports/link.html"
      fi
      printf 'critical=1\nhigh=2\nbad line; rm -rf /\nhigh=x\ntotal=3\n' > "$out/.tf-eu-guard/counts.txt"
    fi
    if [ -n "$STUB_WRITE" ]; then
      mkdir -p "$out/$(dirname "$STUB_WRITE")"
      printf 'NEW\n' > "$out/$STUB_WRITE"
    fi
    exit "${STUB_EXIT:-0}"
    ;;
esac
exit 0
"""


def _run_action(tmp_path, bash, **extra):
    """Run the real scan script with a stub `docker` first on PATH."""
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "docker"
    stub.write_text(STUB_DOCKER, encoding="utf-8")
    stub.chmod(0o755)
    env = {
        "PATH": f"{stub_dir}:{os.environ['PATH']}",
        "GITHUB_WORKSPACE": str(ws),
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "gh_summary"),
        "RUNNER_TEMP_DIR": str(tmp_path),
        "STUB_LOG": str(tmp_path / "argv"),
        "INPUT_PATH": "./terraform",
        "INPUT_IAC_TYPE": "terraform",
        "INPUT_OUTPUT": "dev",
        "INPUT_FRAMEWORK": "all",
        "INPUT_IMAGE": "img:test",
        "INPUT_JOB_SUMMARY": "true",
        **{
            f"INPUT_{n}": ""
            for n in (
                "UPLOAD_REPORTS UPLOAD_SARIF FAIL_ON_SEVERITY FAIL_ON_ANY FAIL_ON_SUPPRESSED "
                "RESIDENCY_POLICY ALLOWED_REGIONS TIMEOUT CHECKOV_JSON OUTPUT_DIR OUTPUT_FILE "
                "CONFIG TRUSTED_CONFIG WAIVERS BASELINE"
            ).split()
        },
    }
    env.update(extra)
    result = subprocess.run(
        [bash, "-c", _scan_run()], env=env, capture_output=True, text=True, cwd=tmp_path
    )
    argv_file = tmp_path / "argv"
    argv = argv_file.read_text(encoding="utf-8").splitlines() if argv_file.exists() else []
    out = tmp_path / "gh_output"
    return result, argv, out.read_text(encoding="utf-8") if out.exists() else ""


def _bash_or_skip() -> str:
    bash = _find_bash()
    if bash is None:
        pytest.skip("bash not available")
    return bash


def test_action_declares_count_outputs():
    outputs = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["outputs"]
    for name in COUNT_NAMES:
        assert outputs[name]["value"] == f"${{{{ steps.scan.outputs.{name} }}}}"
    assert "exit-code" in outputs


def test_action_declares_new_inputs():
    inputs = _inputs()
    for name in ("config", "trusted-config", "waivers", "baseline"):
        assert inputs[name]["default"] == ""
    assert inputs["job-summary"]["default"] == "true"
    text = ACTION.read_text(encoding="utf-8")
    for var in ("CONFIG", "TRUSTED_CONFIG", "WAIVERS", "BASELINE", "JOB_SUMMARY"):
        assert f"INPUT_{var}: ${{{{ inputs." in text


def test_action_writes_job_summary_and_count_outputs(tmp_path):
    bash = _bash_or_skip()
    result, argv, gh_output = _run_action(tmp_path, bash, STUB_EXIT="1")
    assert result.returncode == 1, result.stderr
    assert "tf-eu-guard" in (tmp_path / "gh_summary").read_text(encoding="utf-8")
    assert "critical=1" in gh_output
    assert "total=3" in gh_output
    assert "exit-code=1" in gh_output
    # Only validated lines are forwarded from the (untrusted) container output.
    assert "rm -rf" not in gh_output
    assert "high=x" not in gh_output
    assert "--summary-file" in argv
    assert "/out/.tf-eu-guard/summary.md" in argv
    assert "--counts-file" in argv
    # The scratch directory is not copied back into the workspace.
    assert not (tmp_path / "ws" / ".tf-eu-guard").exists()


def test_action_job_summary_false_skips(tmp_path):
    bash = _bash_or_skip()
    result, _, gh_output = _run_action(tmp_path, bash, INPUT_JOB_SUMMARY="false")
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "gh_summary").exists()
    assert "total=3" in gh_output


def test_action_missing_summary_files_are_skipped(tmp_path):
    bash = _bash_or_skip()
    result, _, gh_output = _run_action(tmp_path, bash, STUB_NO_FILES="1", STUB_EXIT="2")
    assert result.returncode == 2
    assert "exit-code=2" in gh_output
    assert "total=" not in gh_output


def test_action_config_input_passed_through(tmp_path):
    bash = _bash_or_skip()
    ws = tmp_path / "ws"
    result, argv, _ = _run_action(
        tmp_path,
        bash,
        INPUT_CONFIG="cfg/x.yaml",
        INPUT_WAIVERS="w.yaml",
        INPUT_BASELINE=f"{ws}/b.json",
    )
    assert result.returncode == 0, result.stderr
    i = argv.index("--config")
    assert argv[i + 1] == f"{ws}/cfg/x.yaml"
    assert argv[argv.index("--waivers") + 1] == f"{ws}/w.yaml"
    assert argv[argv.index("--baseline") + 1] == f"{ws}/b.json"


def test_action_trusted_config_mounted_read_only(tmp_path):
    bash = _bash_or_skip()
    trusted = tmp_path / "trusted.yaml"
    trusted.write_text("{}\n", encoding="utf-8")
    result, argv, _ = _run_action(tmp_path, bash, INPUT_TRUSTED_CONFIG=str(trusted))
    assert result.returncode == 0, result.stderr
    assert f"{trusted}:/trusted/config.yaml:ro" in argv
    assert argv[argv.index("--config") + 1] == "/trusted/config.yaml"


@pytest.mark.parametrize("kind", ["relative", "missing", "directory", "both"])
def test_action_trusted_config_invalid_is_exit_2(tmp_path, kind):
    bash = _bash_or_skip()
    extra = {
        "relative": {"INPUT_TRUSTED_CONFIG": "c.yaml"},
        "missing": {"INPUT_TRUSTED_CONFIG": str(tmp_path / "nope.yaml")},
        "directory": {"INPUT_TRUSTED_CONFIG": str(tmp_path)},
        "both": {"INPUT_TRUSTED_CONFIG": str(tmp_path / "t.yaml"), "INPUT_CONFIG": "c.yaml"},
    }[kind]
    (tmp_path / "t.yaml").write_text("{}\n", encoding="utf-8")
    result, argv, _ = _run_action(tmp_path, bash, **extra)
    assert result.returncode == 2
    assert "::error::" in result.stderr
    assert argv == []


@pytest.mark.parametrize("name", ["INPUT_WAIVERS", "INPUT_BASELINE", "INPUT_CONFIG"])
def test_action_rejects_dotdot_and_outside_paths(tmp_path, name):
    bash = _bash_or_skip()
    for bad in ("../w.yaml", "/etc/passwd"):
        result, argv, _ = _run_action(tmp_path, bash, **{name: bad})
        assert result.returncode == 2
        assert "::error::" in result.stderr
        assert argv == []


def test_action_rejects_dotdot_in_waivers_input(tmp_path):
    bash = _bash_or_skip()
    result, _, _ = _run_action(tmp_path, bash, INPUT_WAIVERS="a/../../w.yaml")
    assert result.returncode == 2
    assert "::error::" in result.stderr


def test_readme_documents_config_inputs_and_outputs():
    readme = (ACTION.parent / "README.md").read_text(encoding="utf-8")
    for name in ("config", "trusted-config", "waivers", "baseline", "job-summary"):
        assert f"`{name}`" in readme
    assert "`baselined`" in readme


def test_action_ignores_symlinked_summary_and_strips_symlinks_from_copy_back(tmp_path):
    bash = _bash_or_skip()
    secret = tmp_path / "secret.txt"
    secret.write_text("HOSTSECRET\n", encoding="utf-8")
    result, _, gh_output = _run_action(tmp_path, bash, STUB_SYMLINK=str(secret), STUB_EXIT="1")
    assert result.returncode == 1, result.stderr
    summary = tmp_path / "gh_summary"
    assert not summary.exists() or "HOSTSECRET" not in summary.read_text(encoding="utf-8")
    assert "exit-code=1" in gh_output
    assert "::warning::" in result.stdout + result.stderr
    ws = tmp_path / "ws"
    assert not [p for p in ws.rglob("*") if p.is_symlink()]


def test_action_symlinked_meta_dir_is_ignored(tmp_path):
    bash = _bash_or_skip()
    result, _, gh_output = _run_action(tmp_path, bash, INPUT_JOB_SUMMARY="true")
    assert result.returncode == 0
    run = _scan_run()
    assert '[ ! -L "$meta" ]' in run
    assert '[ ! -L "$meta/summary.md" ]' in run
    assert '[ ! -L "$meta/counts.txt" ]' in run


def test_action_trusted_config_inside_workspace_is_exit_2(tmp_path):
    bash = _bash_or_skip()
    inside = tmp_path / "ws" / "c.yaml"
    inside.parent.mkdir(exist_ok=True)
    inside.write_text("{}\n", encoding="utf-8")
    result, argv, _ = _run_action(tmp_path, bash, INPUT_TRUSTED_CONFIG=str(inside))
    assert result.returncode == 2
    assert "::error::" in result.stderr
    assert argv == []


def _assert_copy_back_refused(tmp_path, result, gh_output, outside_file):
    assert result.returncode == 2, result.stderr
    assert "refusing to copy reports through a symlink" in result.stdout + result.stderr
    assert "exit-code=2" in gh_output
    assert not outside_file.exists()


def test_action_refuses_copy_back_through_workspace_symlink(tmp_path):
    bash = _bash_or_skip()
    ws, outside = tmp_path / "ws", tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    (ws / "reports").symlink_to(outside)
    result, _, gh_output = _run_action(tmp_path, bash, STUB_WRITE="reports/x.html")
    _assert_copy_back_refused(tmp_path, result, gh_output, outside / "x.html")


def test_action_refuses_copy_back_through_nested_workspace_symlink(tmp_path):
    bash = _bash_or_skip()
    ws, outside = tmp_path / "ws", tmp_path / "outside"
    (ws / "reports").mkdir(parents=True)
    outside.mkdir()
    (ws / "reports" / "sub").symlink_to(outside)
    result, _, gh_output = _run_action(tmp_path, bash, STUB_WRITE="reports/sub/x.html")
    _assert_copy_back_refused(tmp_path, result, gh_output, outside / "x.html")


def test_action_refuses_copy_back_onto_workspace_file_symlink(tmp_path):
    bash = _bash_or_skip()
    ws, victim = tmp_path / "ws", tmp_path / "victim"
    (ws / "reports").mkdir(parents=True)
    victim.write_text("ORIGINAL", encoding="utf-8")
    (ws / "reports" / "security.html").symlink_to(victim)
    result, _, gh_output = _run_action(tmp_path, bash, STUB_WRITE="reports/security.html")
    assert result.returncode == 2, result.stderr
    assert "exit-code=2" in gh_output
    assert victim.read_text(encoding="utf-8") == "ORIGINAL"


def test_action_copy_back_still_works_for_plain_directories(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws" / "reports").mkdir(parents=True)
    result, _, _ = _run_action(tmp_path, bash, STUB_WRITE="reports/a.html")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "ws" / "reports" / "a.html").read_text(encoding="utf-8") == "NEW\n"


def test_action_trusted_config_symlink_into_workspace_is_exit_2(tmp_path):
    bash = _bash_or_skip()
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "evil.yaml").write_text("{}\n", encoding="utf-8")
    link = tmp_path / "cfg.yaml"
    link.symlink_to(ws / "evil.yaml")
    result, argv, _ = _run_action(tmp_path, bash, INPUT_TRUSTED_CONFIG=str(link))
    assert result.returncode == 2
    assert "::error::" in result.stderr
    assert argv == []


def test_action_refusal_disables_uploads_and_writes_exit_code_once(tmp_path):
    bash = _bash_or_skip()
    ws, outside = tmp_path / "ws", tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    (ws / "reports").symlink_to(outside)
    result, _, gh_output = _run_action(
        tmp_path, bash, STUB_WRITE="reports/x.html", INPUT_UPLOAD_REPORTS="true"
    )
    assert result.returncode == 2
    lines = gh_output.splitlines()
    assert [ln for ln in lines if ln.startswith("upload-reports=")][-1] == "upload-reports=false"
    assert [ln for ln in lines if ln.startswith("upload-sarif=")][-1] == "upload-sarif=false"
    assert sum(ln.startswith("exit-code=") for ln in lines) == 1


def test_action_refuses_committed_html_symlink_in_upload_glob(tmp_path):
    bash = _bash_or_skip()
    ws, victim = tmp_path / "ws", tmp_path / "victim.txt"
    (ws / "reports").mkdir(parents=True)
    victim.write_text("SECRET", encoding="utf-8")
    (ws / "reports" / "evil.html").symlink_to(victim)
    result, _, gh_output = _run_action(
        tmp_path,
        bash,
        STUB_WRITE="reports/dev_report.html",
        INPUT_UPLOAD_REPORTS="true",
        INPUT_OUTPUT="security",
    )
    assert result.returncode == 2, result.stderr
    assert "reports/evil.html" in result.stdout + result.stderr
    assert gh_output.splitlines()[-3:] == [
        "upload-reports=false",
        "upload-sarif=false",
        "exit-code=2",
    ]


def test_action_refuses_committed_sarif_symlink(tmp_path):
    bash = _bash_or_skip()
    ws, victim = tmp_path / "ws", tmp_path / "victim.txt"
    ws.mkdir()
    victim.write_text("SECRET", encoding="utf-8")
    (ws / "tf-eu-guard.sarif").symlink_to(victim)
    result, _, gh_output = _run_action(
        tmp_path, bash, INPUT_OUTPUT="sarif", INPUT_UPLOAD_SARIF="true", STUB_WRITE="x.txt"
    )
    assert result.returncode == 2, result.stderr
    assert "upload-sarif=false" in gh_output.splitlines()[-3:]
    assert victim.read_text(encoding="utf-8") == "SECRET"


def _last(gh_output, key):
    return [ln for ln in gh_output.splitlines() if ln.startswith(f"{key}=")][-1]


def test_action_scan_failure_with_empty_output_still_refuses_symlinked_upload_target(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws" / "reports").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("SECRET", encoding="utf-8")
    (tmp_path / "ws" / "reports" / "evil.html").symlink_to(victim)
    result, _, gh_output = _run_action(
        tmp_path, bash, STUB_NO_FILES="1", STUB_EXIT="2", INPUT_UPLOAD_REPORTS="true"
    )
    assert result.returncode == 2
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def test_action_refuses_committed_html_directory_with_symlink_child(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws" / "reports" / "x.html").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("SECRET", encoding="utf-8")
    (tmp_path / "ws" / "reports" / "x.html" / "leak").symlink_to(victim)
    result, _, gh_output = _run_action(
        tmp_path, bash, STUB_WRITE="reports/dev_report.html", INPUT_UPLOAD_REPORTS="true"
    )
    assert result.returncode == 2, result.stderr
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def test_action_findings_exit_still_enables_requested_uploads(tmp_path):
    bash = _bash_or_skip()
    result, _, gh_output = _run_action(
        tmp_path, bash, STUB_EXIT="1", INPUT_UPLOAD_REPORTS="true", INPUT_UPLOAD_SARIF="yes"
    )
    assert result.returncode == 1, result.stderr
    assert _last(gh_output, "upload-reports") == "upload-reports=true"
    assert _last(gh_output, "upload-sarif") == "upload-sarif=true"


def test_action_early_validation_failure_leaves_uploads_false(tmp_path):
    bash = _bash_or_skip()
    result, _, gh_output = _run_action(
        tmp_path, bash, INPUT_OUTPUT_DIR="../x", INPUT_UPLOAD_REPORTS="true"
    )
    assert result.returncode == 2
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def _link_dir(tmp_path, name, target_rel):
    """workspace/<name> -> external dir that holds <target_rel>."""
    ext = tmp_path / "external"
    (ext / target_rel).parent.mkdir(parents=True, exist_ok=True)
    (ext / target_rel).write_text("SECRET", encoding="utf-8")
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / name).symlink_to(ext)


def test_action_refuses_symlinked_parent_of_nested_output_dir_on_empty_scan(tmp_path):
    bash = _bash_or_skip()
    _link_dir(tmp_path, "out", "reports/secret.html")
    result, _, gh_output = _run_action(
        tmp_path,
        bash,
        STUB_NO_FILES="1",
        STUB_EXIT="2",
        INPUT_OUTPUT_DIR="out/reports",
        INPUT_UPLOAD_REPORTS="true",
    )
    assert result.returncode == 2
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def test_action_refuses_symlinked_parent_of_output_file_on_empty_scan(tmp_path):
    bash = _bash_or_skip()
    _link_dir(tmp_path, "reports", "security.html")
    result, _, gh_output = _run_action(
        tmp_path,
        bash,
        STUB_NO_FILES="1",
        STUB_EXIT="1",
        INPUT_OUTPUT="security",
        INPUT_OUTPUT_DIR="other",
        INPUT_OUTPUT_FILE="reports/security.html",
        INPUT_UPLOAD_REPORTS="true",
    )
    assert result.returncode == 2
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def test_action_refuses_symlinked_output_dir_with_repeated_trailing_slashes(tmp_path):
    bash = _bash_or_skip()
    _link_dir(tmp_path, "reports", "secret.html")
    result, _, gh_output = _run_action(
        tmp_path,
        bash,
        STUB_NO_FILES="1",
        STUB_EXIT="2",
        INPUT_OUTPUT_DIR="reports//",
        INPUT_UPLOAD_REPORTS="true",
    )
    assert result.returncode == 2
    assert _last(gh_output, "upload-reports") == "upload-reports=false"


def test_action_plain_nested_output_dir_still_uploads(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws" / "out" / "reports").mkdir(parents=True)
    result, _, gh_output = _run_action(
        tmp_path,
        bash,
        STUB_WRITE="out/reports/a.html",
        INPUT_OUTPUT_DIR="out/reports",
        INPUT_UPLOAD_REPORTS="true",
    )
    assert result.returncode == 0, result.stderr
    assert _last(gh_output, "upload-reports") == "upload-reports=true"


def test_action_refusal_message_neutralises_workflow_commands_in_filenames(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws" / "reports").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("SECRET", encoding="utf-8")
    (tmp_path / "ws" / "reports" / "a\n::stop-commands::x.html").symlink_to(victim)
    result, _, _ = _run_action(tmp_path, bash, INPUT_UPLOAD_REPORTS="true")
    assert result.returncode == 2
    lines = (result.stdout + result.stderr).splitlines()
    assert not [ln for ln in lines if ln.startswith("::stop-commands::")]
    assert any(ln.startswith("::error::") and "%0A::stop-commands::x" in ln for ln in lines)


def test_action_copy_back_failure_leaves_uploads_false(tmp_path):
    bash = _bash_or_skip()
    (tmp_path / "ws").mkdir()
    (tmp_path / "ws" / "reports").write_text("not a directory", encoding="utf-8")
    result, _, gh_output = _run_action(
        tmp_path, bash, STUB_WRITE="reports/x.html", INPUT_UPLOAD_REPORTS="true"
    )
    assert result.returncode != 0
    assert _last(gh_output, "upload-reports") == "upload-reports=false"
