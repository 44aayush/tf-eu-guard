"""Tests for tools/smoke_check.py — the baseline regression guard itself.

smoke_check.py exists to catch silent-0 regressions (a scan path that quietly
returns no findings), so a bug in *its own* comparison logic would go
undetected the same way. These tests exercise the pass/fail decisions against
mocked baselines and mocked scans — no real Checkov run required.

Hermetic: ``_scan`` is monkeypatched; ``check_iac_type``/``main`` read a
temporary baseline file.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# tools/ is not a package; put it on sys.path to import its modules (and let
# ``--cov=tools`` measure them).
TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import smoke_check  # noqa: E402


@pytest.fixture
def baseline_file(tmp_path, monkeypatch):
    """A temporary baselines file; returns a mutator so each test can shape it."""
    path = tmp_path / "smoke_baselines.json"
    data = {
        "terraform": {"vulnerable": {}, "compliant": {}},
    }
    path.write_text(json.dumps(data))
    monkeypatch.setattr(smoke_check, "BASELINE_FILE", path)
    return path


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace the real CLI-scan with a count the test controls."""
    counts = {}

    def _scan(path, iac_type):
        return counts.get(path, 0)

    monkeypatch.setattr(smoke_check, "_scan", _scan)
    return counts


# --- vulnerable examples: min is a floor ------------------------------------------


def test_vulnerable_below_min_fails(baseline_file, fake_scan):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 52, "min": 30}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 3
    failures = smoke_check.check_iac_type("terraform")
    assert len(failures) == 1
    assert "returned 3 mapped findings" in failures[0]
    assert "floor 30" in failures[0]
    assert "scan path is broken" in failures[0]


def test_vulnerable_at_min_passes(baseline_file, fake_scan):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 52, "min": 30}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 30
    assert smoke_check.check_iac_type("terraform") == []


def test_vulnerable_zero_fails_even_with_zero_min(baseline_file, fake_scan):
    """The shipped-bug guard: zero findings on a vulnerable example is always
    a failure — a near-zero count means the scan path is broken."""
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 5, "min": 0}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 0
    assert len(smoke_check.check_iac_type("terraform")) == 1


def test_vulnerable_above_expected_passes_with_note(baseline_file, fake_scan, capsys):
    """Counts above the measured baseline are tolerated (registry growth) —
    reported as a non-fatal note, not a failure."""
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 52, "min": 30}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 60
    assert smoke_check.check_iac_type("terraform") == []
    assert "returned 60 findings; baseline says 52" in capsys.readouterr().err


# --- compliant examples: max is a ceiling -----------------------------------------


def test_compliant_above_max_fails(baseline_file, fake_scan):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["compliant"]["examples/clean"] = {"expected": 0, "max": 0}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/clean"] = 2
    failures = smoke_check.check_iac_type("terraform")
    assert len(failures) == 1
    assert "Something is firing on the compliant fixture" in failures[0]


def test_compliant_at_max_passes(baseline_file, fake_scan):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["compliant"]["examples/clean"] = {"expected": 0, "max": 0}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/clean"] = 0
    assert smoke_check.check_iac_type("terraform") == []


def test_unknown_iac_type_is_an_error(baseline_file, fake_scan):
    with pytest.raises(RuntimeError, match="no baseline entry"):
        smoke_check.check_iac_type("dockerfile")


# --- main() exit codes ------------------------------------------------------------


def _run_main(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", ["smoke_check.py", *argv])
    return smoke_check.main()


def test_main_ok_exits_zero(monkeypatch, baseline_file, fake_scan, capsys):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 5, "min": 1}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 5
    assert _run_main(monkeypatch, ["--iac-type", "terraform"]) == 0
    assert "smoke check OK (1 example(s), terraform)" in capsys.readouterr().out


def test_main_failure_exits_two(monkeypatch, baseline_file, fake_scan, capsys):
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 5, "min": 1}
    baseline_file.write_text(json.dumps(baseline))
    fake_scan["examples/vuln"] = 0
    assert _run_main(monkeypatch, ["--iac-type", "terraform"]) == 2
    err = capsys.readouterr().err
    assert "SMOKE CHECK FAILED:" in err
    assert "examples/vuln" in err  # specific, with counts — never just "failed"


def test_main_error_exits_one(monkeypatch, baseline_file, fake_scan, capsys):
    def boom(path, iac_type):
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(smoke_check, "_scan", boom)
    baseline = json.loads(baseline_file.read_text())
    baseline["terraform"]["vulnerable"]["examples/vuln"] = {"expected": 5, "min": 1}
    baseline_file.write_text(json.dumps(baseline))
    assert _run_main(monkeypatch, ["--iac-type", "terraform"]) == 1
    assert "smoke check error" in capsys.readouterr().err


def test_main_all_fans_out_over_every_type(monkeypatch, baseline_file, fake_scan):
    baseline = json.loads(baseline_file.read_text())
    for iac_type in smoke_check.IAC_TYPES:
        baseline[iac_type] = {
            "vulnerable": {f"examples/vuln-{iac_type}": {"expected": 1, "min": 1}},
            "compliant": {f"examples/clean-{iac_type}": {"expected": 0, "max": 0}},
        }
    baseline_file.write_text(json.dumps(baseline))
    fake_scan.update({f"examples/vuln-{t}": 1 for t in smoke_check.IAC_TYPES})
    fake_scan.update({f"examples/clean-{t}": 0 for t in smoke_check.IAC_TYPES})
    assert _run_main(monkeypatch, ["--iac-type", "all"]) == 0


def test_main_requires_iac_type(monkeypatch):
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, [])


# --- _scan: the CLI subprocess wrapper (mocked subprocess) -----------------------


def test_scan_counts_json_findings(monkeypatch):
    def fake_run(cmd, **kwargs):
        assert cmd[:4] == [sys.executable, "-m", "tf_eu_guard.cli", "scan"]
        assert "--iac-type" in cmd and "--output" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='[{"a": 1}, {"a": 2}]', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert smoke_check._scan("some/path", "terraform") == 2


def test_scan_cli_error_raises(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="exited 1"):
        smoke_check._scan("some/path", "terraform")


def test_scan_invalid_json_raises(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="not json", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="invalid JSON"):
        smoke_check._scan("some/path", "terraform")


def test_scan_non_array_json_raises(monkeypatch):
    """A JSON object (not an array) is a contract violation, not a count."""
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": {}}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="expected a JSON array"):
        smoke_check._scan("some/path", "terraform")
