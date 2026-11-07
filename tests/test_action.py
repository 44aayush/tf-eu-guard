"""Static and shell-level checks for the composite GitHub Action."""

import subprocess
from pathlib import Path

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
        "INPUT_CHECKOV_JSON",
        "INPUT_OUTPUT_DIR",
        "INPUT_OUTPUT_FILE",
    ):
        assert f'"${variable}"' in run


def test_action_argument_array_preserves_hostile_input_literally(tmp_path):
    sentinel = tmp_path / "injection"
    hostile = f'a"; touch {sentinel}; $(printf pwned) whitespace'
    script = 'args=(); args+=("$INPUT_PATH"); printf "%s\\n" "${args[0]}"'
    result = subprocess.run(
        ["bash", "-c", script],
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
        "inputs.upload-reports == 'true' && "
        "(inputs.output == 'all' || ((inputs.output == 'security' || "
        "inputs.output == 'auditor') && inputs.output-file == ''))"
    ) in text
    assert "path: ${{ inputs.output-dir || 'reports' }}/*.html" in text
    assert "inputs.output-file != ''" in text
    assert "path: ${{ inputs.output-file }}" in text
    assert "if-no-files-found: error" in text


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
    assert "category: terraform-source" in text
    assert "category: terraform-custom" in text


def test_action_e2e_covers_custom_single_html_destination():
    text = ACTION_E2E.read_text(encoding="utf-8")
    assert "output: security" in text
    assert "output-file: action-artifacts/custom-security.html" in text
    assert "test -f action-artifacts/custom-security.html" in text
