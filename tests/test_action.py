"""Static and shell-level checks for the composite GitHub Action."""

import subprocess
from pathlib import Path

ACTION = Path(__file__).parents[1] / "action.yml"


def test_action_inputs_are_passed_through_env_not_shell_code():
    text = ACTION.read_text(encoding="utf-8")
    run = text.split("      run: |", 1)[1].split("\n\n    - name:", 1)[0]
    assert "${{ inputs." not in run
    for variable in (
        "INPUT_PATH", "INPUT_IAC_TYPE", "INPUT_OUTPUT", "INPUT_FRAMEWORK",
        "INPUT_FAIL_ON_SEVERITY", "INPUT_FAIL_ON_ANY", "INPUT_CHECKOV_JSON",
        "INPUT_OUTPUT_DIR", "INPUT_OUTPUT_FILE",
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
