"""Static and shell-level checks for the composite GitHub Action."""

import os
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
    assert run.index("upload-reports=true") < run.index("docker run")
    assert run.index("upload-sarif=true") < run.index("docker run")


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
