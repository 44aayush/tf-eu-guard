"""N-10: the optional Checkov ``secrets`` framework (``--secrets``)."""

import json
import subprocess
from pathlib import Path

import pytest

from tests.cli_helpers import FIXTURE, run_cli
from tf_eu_guard.checkov.json import (
    load_checkov_json,
    normalize_checkov_output,
    validate_scan_output,
)
from tf_eu_guard.checkov.process import run_checkov
from tf_eu_guard.checkov.types import CheckovRuntimeError
from tf_eu_guard.cli.pipeline import default_registry_dir
from tf_eu_guard.mapping.loader import load_registry
from tf_eu_guard.mapping.schema import CHECK_ID_RE

FAKE_KEY = "AKIAFAKEFAKEFAKEFAKE"
SECRET_HASH = "0123456789abcdef0123456789abcdef01234567"  # Checkov's ``resource`` for secrets


def _element(check_type, failed=(), parsing_errors=0, passed=(), skipped=()):
    return {
        "check_type": check_type,
        "summary": {"parsing_errors": parsing_errors},
        "results": {
            "passed_checks": list(passed),
            "failed_checks": list(failed),
            "skipped_checks": list(skipped),
        },
    }


def _secret_check(check_id="CKV_SECRET_2", name="AWS Access Key"):
    return {
        "check_id": check_id,
        "check_name": name,
        "resource": SECRET_HASH,
        "file_path": "/main.tf",
        "file_line_range": [5, 5],
        "guideline": None,
        "code_block": [[5, f'  k = "{FAKE_KEY}"\n']],
        "check_result": {"result": "FAILED", "evaluated_keys": [FAKE_KEY]},
        "details": [FAKE_KEY],
    }


def test_secrets_flag_adds_framework(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        out = json.dumps(_element("terraform") if "secrets" not in cmd else [_element("terraform")])
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr("tf_eu_guard.checkov.process.subprocess.run", fake_run)
    run_checkov(tmp_path, "terraform", secrets=True)
    cmd = seen["cmd"]
    i = cmd.index("--framework")
    assert cmd[i : i + 3] == ["--framework", "terraform", "secrets"]
    run_checkov(tmp_path, "terraform")
    assert "secrets" not in seen["cmd"]


def test_normalize_merges_secrets_element():
    data = [
        _element("terraform", failed=[{"check_id": "CKV_AWS_16"}]),
        _element("secrets", failed=[_secret_check()]),
    ]
    merged = normalize_checkov_output(data, "terraform", ("secrets",))
    assert [c["check_id"] for c in merged["results"]["failed_checks"]] == [
        "CKV_AWS_16",
        "CKV_SECRET_2",
    ]
    secret = merged["results"]["failed_checks"][1]
    assert FAKE_KEY not in json.dumps(merged)
    assert "code_block" not in secret and "details" not in secret
    assert "0123456789abcdef" not in secret["resource"]
    assert len(data[1]["results"]["failed_checks"]) == 1  # input not mutated
    assert "code_block" in data[1]["results"]["failed_checks"][0]


def test_normalize_missing_secrets_element_is_empty():
    merged = normalize_checkov_output([_element("terraform")], "terraform", ("secrets",))
    assert merged["results"]["failed_checks"] == []


def test_normalize_without_extra_ignores_secrets_element():
    data = [_element("terraform"), _element("secrets", failed=[_secret_check()])]
    assert normalize_checkov_output(data, "terraform")["results"]["failed_checks"] == []


def test_secrets_parsing_errors_fail_closed():
    data = [_element("terraform"), _element("secrets", parsing_errors=2)]
    merged = normalize_checkov_output(data, "terraform", ("secrets",))
    assert merged["summary"]["parsing_errors"] == 2
    with pytest.raises(CheckovRuntimeError, match="2 parsing error"):
        validate_scan_output(data, "terraform", ("secrets",))


def test_secrets_parsing_errors_fail_closed_for_checkov_json(tmp_path):
    path = tmp_path / "in.json"
    path.write_text(json.dumps([_element("terraform"), _element("secrets", parsing_errors=1)]))
    with pytest.raises(CheckovRuntimeError, match="parsing error"):
        load_checkov_json(path, "terraform", ("secrets",))


def _write_secret_fixture(tmp_path: Path) -> Path:
    base = json.loads(Path(FIXTURE).read_text())
    base = base[0] if isinstance(base, list) else base
    data = [base, _element("secrets", failed=[_secret_check()])]
    path = tmp_path / "with-secrets.json"
    path.write_text(json.dumps(data))
    return path


def test_secret_finding_is_mapped(monkeypatch, tmp_path, capsys):
    path = _write_secret_fixture(tmp_path)
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(path), "--secrets",
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    out = capsys.readouterr().out
    findings = json.loads(out)["findings"]
    secret = [f for f in findings if f["check_id"] == "CKV_SECRET_2"]
    assert len(secret) == 1
    assert any(a["article"] == "Art. 21(2)(e)" for a in secret[0]["articles"])
    assert secret[0]["severity"] == "HIGH"


def test_secret_without_flag_is_not_reported(monkeypatch, tmp_path, capsys):
    path = _write_secret_fixture(tmp_path)
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(path), "--output", "json")
    assert "CKV_SECRET_2" not in capsys.readouterr().out


def test_checkov_json_without_secrets_element_is_not_an_error(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(Path(FIXTURE).resolve()), "--secrets")
    assert "CKV_SECRET" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("fmt", "extra"),
    [
        ("dev", []),
        ("json", []),
        ("json", ["--json-format", "object"]),
        ("sarif", []),
        ("security", []),
        ("auditor", []),
        ("all", []),
    ],
)
def test_secret_value_never_in_report(fmt, extra, monkeypatch, tmp_path, capsys):
    path = _write_secret_fixture(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    args = ["--checkov-json", str(path), "--secrets", "--output", fmt, *extra]
    args += ["--output-dir", str(out_dir)]
    if fmt in ("security", "auditor"):
        args += ["--output-file", str(out_dir / "report.html")]
    code = run_cli(monkeypatch, tmp_path, *args)
    captured = capsys.readouterr()
    assert code in (0, 1), captured.err
    assert "CKV_SECRET_2" in captured.out + "".join(
        p.read_text(encoding="utf-8") for p in out_dir.rglob("*") if p.is_file()
    )
    assert FAKE_KEY not in captured.out + captured.err
    assert SECRET_HASH not in captured.out + captured.err
    for p in (q for q in tmp_path.rglob("*") if q.is_file() and q != path):
        assert FAKE_KEY.encode() not in p.read_bytes(), p
        assert SECRET_HASH.encode() not in p.read_bytes(), p


def test_every_secrets_registry_entry_validates():
    registry = load_registry(default_registry_dir())
    secrets = {k: v for k, v in registry.items() if k.startswith("CKV_SECRET_")}
    assert len(secrets) == 19
    for check_id, mapping in secrets.items():
        assert CHECK_ID_RE.fullmatch(check_id)
        assert mapping.severity.value == "HIGH"
        assert {(a.framework.value, a.article) for a in mapping.articles} == {
            ("NIS2", "Art. 21(2)(e)"),
            ("GDPR", "Art. 32(1)(b)"),
        }
        assert mapping.check_name in mapping.risk_explanation
    assert registry["CKV_SECRET_2"].check_name == "AWS Access Key"


@pytest.mark.parametrize("check_id", ["CKV_SECRET_2", "CKV_SECRET_380"])
def test_check_id_pattern_accepts_secret_ids(check_id):
    assert CHECK_ID_RE.fullmatch(check_id)


@pytest.mark.parametrize("check_id", ["CKV_SECRET_", "CKV_SECRETS_1", "CKV_SECRET_x"])
def test_check_id_pattern_rejects_malformed_secret_ids(check_id):
    assert not CHECK_ID_RE.fullmatch(check_id)
