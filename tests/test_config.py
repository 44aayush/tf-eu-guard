"""Project configuration file (N-02) and the weakening-settings disclosure."""

import json
from pathlib import Path

import pytest
from cli_helpers import FIXTURE, run_cli
from jsonschema import Draft202012Validator

from tf_eu_guard.config import ConfigError, find_config, load_config

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "tf_eu_guard/schemas/report.schema.json").read_text())


def _cfg(tmp_path, text, name=".tf-eu-guard.yaml"):
    path = tmp_path / name
    path.write_text(text)
    return path


def _one_finding(tmp_path):
    """A Checkov doc holding only the HIGH check CKV_AWS_16."""
    doc = json.loads((ROOT / FIXTURE).read_text())
    doc["results"]["failed_checks"] = [
        c for c in doc["results"]["failed_checks"] if c["check_id"] == "CKV_AWS_16"
    ]
    path = tmp_path / "one.json"
    path.write_text(json.dumps(doc))
    return path


def _scan(monkeypatch, tmp_path, *args, source=None):
    return run_cli(monkeypatch, tmp_path, "--checkov-json", str(source or ROOT / FIXTURE), *args)


def _object(monkeypatch, tmp_path, capsys, *args):
    rc = _scan(monkeypatch, tmp_path, "--output", "json", "--json-format", "object", *args)
    return rc, json.loads(capsys.readouterr().out)


def test_config_sets_defaults(tmp_path):
    cfg = _cfg(
        tmp_path,
        "fail_on_severity: high\nfail_on_any: true\ntimeout: 5\nframework: nis2\n"
        "residency_policy: custom\nallowed_regions: [eu-west-1, eu-north-1]\n",
    )
    values = load_config(cfg)
    assert values["fail_on_severity"] == "HIGH"
    assert values["fail_on_any"] is True
    assert values["timeout"] == 5.0
    assert values["framework"] == "nis2"
    assert values["allowed_regions"] == ("eu-north-1", "eu-west-1")


def test_cli_overrides_config(monkeypatch, tmp_path, capsys):
    one = _one_finding(tmp_path)
    cfg = _cfg(tmp_path, "fail_on_severity: critical\n")
    assert _scan(monkeypatch, tmp_path, "--config", str(cfg), "--output", "json", source=one) == 0
    capsys.readouterr()
    args = ("--config", str(cfg), "--output", "json", "--fail-on-severity", "low")
    assert _scan(monkeypatch, tmp_path, *args, source=one) == 1


def test_config_gate_applies(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, "fail_on_severity: low\n")
    assert _scan(monkeypatch, tmp_path, "--config", str(cfg), "--output", "json") == 1


def test_config_lists_concatenate_with_cli(monkeypatch, tmp_path, capsys):
    _cfg(tmp_path, "exclude: [alpha]\n")
    rc, doc = _object(
        monkeypatch, tmp_path, capsys, "--config", ".tf-eu-guard.yaml", "--exclude", "beta"
    )
    assert rc == 0
    lines = doc["scan"]["weakening_settings"]
    assert lines.index("exclude: alpha") < lines.index("exclude: beta")


@pytest.mark.parametrize(
    "text, needle",
    [
        ("fail_on_severiti: high\n", "fail_on_severiti"),
        ("residency_policy: mars\n", "residency_policy"),
        ("fail_on_any: 'yes'\n", "fail_on_any"),
        ("exclude: a\n", "exclude"),
        ("timeout: -1\n", "timeout"),
        ("- a\n", "mapping"),
        ("a: [\n", "YAML"),
        ("exclude: [a]\nexclude: [b]\n", "duplicate"),
        ("severity_overrides: {CKV_AWS_16: SEVERE}\n", "CKV_AWS_16"),
    ],
)
def test_invalid_config_exits_2(monkeypatch, tmp_path, capsys, text, needle):
    cfg = _cfg(tmp_path, text)
    with pytest.raises(ConfigError):
        load_config(cfg)
    assert _scan(monkeypatch, tmp_path, "--config", str(cfg)) == 2
    assert needle in capsys.readouterr().err


def test_missing_explicit_config_exits_2(monkeypatch, tmp_path):
    assert _scan(monkeypatch, tmp_path, "--config", "nope.yaml") == 2


def test_config_residency_validation_still_applies(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, "residency_policy: custom\n")
    with pytest.raises(SystemExit) as exc:
        _scan(monkeypatch, tmp_path, "--config", str(cfg))
    assert exc.value.code == 2


def test_config_paths_relative_to_config_file(tmp_path):
    (tmp_path / "conf").mkdir()
    cfg = _cfg(tmp_path / "conf", "waivers: w.yaml\nregistry_dirs: [reg]\n", "c.yaml")
    values = load_config(cfg)
    assert values["waivers"] == tmp_path / "conf" / "w.yaml"
    assert values["registry_dirs"] == [tmp_path / "conf" / "reg"]


def test_discovered_config_in_scan_root(tmp_path):
    _cfg(tmp_path, "fail_on_any: true\n")
    assert find_config(tmp_path) == tmp_path / ".tf-eu-guard.yaml"
    plan = tmp_path / "plan.json"
    assert find_config(plan) == tmp_path / ".tf-eu-guard.yaml"
    (tmp_path / "sub").mkdir()
    assert find_config(tmp_path / "sub") is None
    assert find_config(None) is None


def test_no_config_skips_explicit_config(monkeypatch, tmp_path, capsys):
    cfg = _cfg(tmp_path, "exclude: [zzz]\n")
    rc, doc = _object(monkeypatch, tmp_path, capsys, "--config", str(cfg), "--no-config")
    assert rc == 0 and doc["scan"]["weakening_settings"] == []


def test_checkov_json_does_not_discover_config(monkeypatch, tmp_path, capsys):
    _cfg(tmp_path, "exclude: [zzz]\n")
    rc, doc = _object(monkeypatch, tmp_path, capsys)
    assert rc == 0 and doc["scan"]["weakening_settings"] == []


def test_severity_override_applies(monkeypatch, tmp_path, capsys):
    cfg = _cfg(tmp_path, "severity_overrides:\n  CKV_AWS_16: low\n")
    one = _one_finding(tmp_path)
    rc, doc = _object(
        monkeypatch, tmp_path, capsys, "--config", str(cfg), "--fail-on-severity", "high"
    )
    del rc
    capsys.readouterr()
    rc = _scan(
        monkeypatch, tmp_path, "--config", str(cfg), "--fail-on-severity", "high", source=one
    )
    assert rc == 0
    by_id = {f["check_id"]: f["severity"] for f in doc["findings"]}
    assert by_id["CKV_AWS_16"] == "LOW"
    assert "severity override: CKV_AWS_16 HIGH→LOW" in doc["scan"]["weakening_settings"]


def test_unknown_override_warns_on_stderr(monkeypatch, tmp_path, capsys):
    cfg = _cfg(tmp_path, "severity_overrides:\n  CKV_NOPE_1: LOW\n")
    _scan(monkeypatch, tmp_path, "--config", str(cfg), "--output", "json")
    assert "CKV_NOPE_1" in capsys.readouterr().err


def test_weakening_settings_in_json_and_dev_output(monkeypatch, tmp_path, capsys):
    cfg = _cfg(tmp_path, "exclude: [tests/fixtures]\nseverity_overrides: {CKV_AWS_16: LOW}\n")
    rc, doc = _object(monkeypatch, tmp_path, capsys, "--config", str(cfg))
    lines = doc["scan"]["weakening_settings"]
    assert f"config: {cfg}" in lines and "exclude: tests/fixtures" in lines
    Draft202012Validator(SCHEMA).validate(doc)

    assert _scan(monkeypatch, tmp_path, "--config", str(cfg)) == rc
    out = capsys.readouterr().out
    assert "Scan settings that reduce findings" in out
    assert "exclude: tests/fixtures" in out


def test_weakening_settings_empty_prints_nothing(monkeypatch, tmp_path, capsys):
    _scan(monkeypatch, tmp_path)
    assert "Scan settings that reduce findings" not in capsys.readouterr().out


def test_weakening_settings_in_html_and_sarif(monkeypatch, tmp_path, capsys):
    cfg = _cfg(tmp_path, "exclude: ['<b>x</b>']\n")
    out_dir = tmp_path / "out"
    _scan(
        monkeypatch, tmp_path, "--config", str(cfg), "--output", "all", "--output-dir", str(out_dir)
    )
    capsys.readouterr()
    pages = list(out_dir.glob("*.html"))
    assert len(pages) == 3
    for page in pages:
        text = page.read_text()
        assert "Scan settings that reduce findings" in text
        assert "&lt;b&gt;x&lt;/b&gt;" in text and "<b>x</b>" not in text
    _scan(monkeypatch, tmp_path, "--config", str(cfg), "--output", "sarif")
    run = json.loads(capsys.readouterr().out)["runs"][0]
    assert "exclude: <b>x</b>" in run["properties"]["weakeningSettings"]


def test_waiver_and_overlay_listed(monkeypatch, tmp_path, capsys):
    (tmp_path / "reg").mkdir()
    (tmp_path / "reg" / "o.yaml").write_text(
        "CKV_AWS_16:\n  check_name: N\n  severity: LOW\n  risk: r\n  remediation: f\n"
        "  articles:\n    - {framework: NIS2, article: 'Art. 21(2)(h)', title: 'Policies and procedures on the use of cryptography and encryption'}\n"
    )
    (tmp_path / "w.yaml").write_text(
        "schema_version: 1\nwaivers:\n  - {check_id: CKV_AWS_16, resource: aws_db_instance.app_db,"
        " owner: o, reason: r, expires: 2099-01-01}\n"
    )
    cfg = _cfg(tmp_path, "waivers: w.yaml\nregistry_dirs: [reg]\n")
    rc, doc = _object(monkeypatch, tmp_path, capsys, "--config", str(cfg))
    lines = doc["scan"]["weakening_settings"]
    assert f"waivers: {tmp_path / 'w.yaml'} (1 entries)" in lines
    assert f"registry overlay: {tmp_path / 'reg' / 'o.yaml'}" in lines


def test_non_utf8_config_exits_2(monkeypatch, tmp_path, capsys):
    cfg = tmp_path / ".tf-eu-guard.yaml"
    cfg.write_bytes(b"\xff\xfe bad")
    assert _scan(monkeypatch, tmp_path, "--config", str(cfg)) == 2
    assert "cannot read config file" in capsys.readouterr().err


def test_json_array_discloses_settings_on_stderr(monkeypatch, tmp_path, capsys):
    _scan(monkeypatch, tmp_path, "--output", "json", "--exclude", "x")
    captured = capsys.readouterr()
    assert "exclude: x" in captured.err
    assert "Scan settings that reduce findings:" in captured.err
    assert isinstance(json.loads(captured.out), list)


def test_var_files_key_relative_and_concatenated(tmp_path):
    cfg = _cfg(tmp_path, "var_files: [prod.tfvars]\n")
    assert load_config(cfg)["var_files"] == [tmp_path / "prod.tfvars"]


def test_no_discovery_ignores_scan_root_config(monkeypatch, tmp_path, capsys):
    doc = json.loads(_one_finding(tmp_path).read_text())
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: doc)
    src = tmp_path / "src"
    src.mkdir()
    _cfg(src, "severity_overrides: {CKV_AWS_16: INFO}\n")
    gate = [str(src), "--fail-on-severity", "HIGH", "--output", "json"]
    assert run_cli(monkeypatch, tmp_path, *gate) == 0
    capsys.readouterr()
    assert run_cli(monkeypatch, tmp_path, *gate, "--no-discovery") == 1
    err = capsys.readouterr().err
    assert f"Note: --no-discovery: ignored {src / '.tf-eu-guard.yaml'}" in err
