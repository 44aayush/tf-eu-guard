"""Golden-output guard for the report layer, plus ReportContext field copying."""

import os
import re
import shutil
from pathlib import Path

import pytest

from tests.cli_helpers import FIXTURE, run_cli
from tf_eu_guard import __version__

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "report-golden"
REPO_ROOT = Path(__file__).resolve().parent.parent

# Each case: (golden name, extension, CLI arguments after --output-file/--output).
CASES = [
    ("dev", "txt", ["--output", "dev"]),  # terminal report: stdout only
    ("security", "html", ["--output", "security"]),
    ("auditor", "html", ["--output", "auditor"]),
    ("sarif", "json", ["--output", "sarif"]),
    ("json-object", "json", ["--output", "json", "--json-format", "object"]),
    ("json-array", "json", ["--output", "json", "--json-format", "array"]),
    ("markdown", "md", ["--output", "markdown"]),
    ("csv", "csv", ["--output", "csv"]),
]
# Formats that can also print the report to stdout.
STDOUT_CASES = [case for case in CASES if case[0] not in ("security", "auditor")]
FILE_CASES = [case for case in CASES if case[0] != "dev"]

_VOLATILE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"  # ISO timestamps
    r"|\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"  # report-header timestamps
    r"|\b[0-9a-f]{32}\b"  # uuid4 hex
    r"|\b[0-9a-f]{64}\b"  # registry SHA-256 (changes with every registry edit)
)


def normalise(text: str) -> str:
    """Replace timestamps, uuids, digests and the tool version so reports compare across runs."""
    return _VOLATILE.sub("<VOLATILE>", text).replace(__version__, "<VERSION>")


def _check_golden(name: str, extension: str, text: str) -> None:
    golden = GOLDEN_DIR / f"{name}.{extension}"
    text = normalise(text)
    if os.environ.get("TFEG_UPDATE_GOLDEN") == "1":
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(text, encoding="utf-8", newline="")
    assert text == golden.read_bytes().decode("utf-8"), f"{golden.name} drifted"


@pytest.mark.parametrize(
    ("name", "extension", "output"), FILE_CASES, ids=[c[0] for c in FILE_CASES]
)
def test_reports_are_byte_identical(monkeypatch, tmp_path, name, extension, output):
    shutil.copy(REPO_ROOT / FIXTURE, tmp_path / "scan.json")
    out = tmp_path / f"report.{extension}"
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        "scan.json",
        "--no-config",
        "--show-unmapped",
        *output,
        "--output-file",
        out.name,
    )
    assert rc in (0, 1)
    _check_golden(name, extension, out.read_bytes().decode("utf-8"))


@pytest.mark.parametrize(
    ("name", "extension", "output"), STDOUT_CASES, ids=[c[0] for c in STDOUT_CASES]
)
def test_stdout_reports_are_byte_identical(monkeypatch, tmp_path, capsys, name, extension, output):
    shutil.copy(REPO_ROOT / FIXTURE, tmp_path / "scan.json")
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        "scan.json",
        "--no-config",
        "--show-unmapped",
        *output,
    )
    assert rc in (0, 1)
    _check_golden(f"stdout-{name}", extension, capsys.readouterr().out)
