"""Tests for the stable Python API (tf_eu_guard.scan)."""

import inspect
import json
from pathlib import Path

import pytest

import tf_eu_guard
from tf_eu_guard.cli.parser import build_parser
from tf_eu_guard.models import Framework

FIXTURE = Path(__file__).parent / "fixtures" / "checkov-vulnerable-tf.json"


def test_scan_checkov_json_returns_result():
    result = tf_eu_guard.scan(checkov_json=FIXTURE)
    assert isinstance(result, tf_eu_guard.ScanResult)
    assert "CKV_AWS_16" in {f.check_id for f in result.findings}
    assert result.requirements
    assert result.provenance["options"]["framework"] == "all"


def test_scan_does_not_print(capsys):
    tf_eu_guard.scan(checkov_json=FIXTURE)
    assert capsys.readouterr().out == ""


def test_scan_framework_filter():
    result = tf_eu_guard.scan(checkov_json=FIXTURE, framework="gdpr")
    assert result.findings
    assert all(Framework.GDPR in f.frameworks for f in result.findings)
    assert {r.requirement.framework.value.lower() for r in result.requirements} == {"gdpr"}


def test_scan_invalid_policy_raises_value_error():
    with pytest.raises(ValueError, match="allowed-regions"):
        tf_eu_guard.scan(checkov_json=FIXTURE, allowed_regions=["eu-west-1"])


def test_scan_custom_regions_become_cli_flag():
    result = tf_eu_guard.scan(
        checkov_json=FIXTURE, residency_policy="custom", allowed_regions=["eu-west-1"]
    )
    assert result.provenance["options"]["allowed_regions"] == ["eu-west-1"]


def test_api_and_cli_defaults_agree():
    parser_defaults = vars(build_parser().parse_args(["scan", "."]))
    for name, param in inspect.signature(tf_eu_guard.scan).parameters.items():
        if name == "path":
            continue
        default = param.default
        expected = parser_defaults[name]
        if isinstance(default, tuple):
            default, expected = list(default), list(expected)
        assert default == expected, name


def test_scan_result_is_json_serialisable_provenance():
    json.dumps(tf_eu_guard.scan(checkov_json=FIXTURE).provenance)


def _config_dir(tmp_path):
    (tmp_path / ".tf-eu-guard.yaml").write_text("framework: gdpr\n")
    return tmp_path


def _frameworks(result):
    return {a.framework.value for f in result.findings for a in f.articles}


def test_scan_config_overrides_default_keywords_and_no_config_wins(monkeypatch, tmp_path):
    doc = json.loads(FIXTURE.read_text())
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: doc)
    root = _config_dir(tmp_path)
    assert {f.lower() for f in _frameworks(tf_eu_guard.scan(root))} == {"gdpr"}
    result = tf_eu_guard.scan(root, framework="all", no_config=True)
    assert len(_frameworks(result)) > 1


def test_api_scan_always_has_provenance():
    result = tf_eu_guard.scan(checkov_json=FIXTURE)
    assert result.provenance["tool_version"]
