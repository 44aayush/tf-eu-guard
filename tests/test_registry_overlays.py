"""Tests for overlay registries (--registry-dir) and ``registry validate``."""

from pathlib import Path

import pytest

from tests.cli_helpers import FIXTURE, run_cli, run_command
from tf_eu_guard.cli.pipeline import default_registry_dir
from tf_eu_guard.mapping.loader import (
    RegistryValidationError,
    load_registry_with_overlays,
)
from tf_eu_guard.models import Severity


def _entry(check_id: str, article: str):
    return (
        f"{check_id}:\n  check_name: N\n  severity: LOW\n  risk: r\n  remediation: f\n"
        f"  articles:\n    - {{framework: NIS2, article: '{article}', title: 'Whatever'}}\n"
    )


def _overlay(tmp_path: Path, name: str, content: str, filename: str = "extra.yaml") -> Path:
    directory = tmp_path / name
    directory.mkdir()
    (directory / filename).write_text(content, encoding="utf-8")
    return directory


def _policy(check_id: str, severity: str = "LOW", title: str = "Anything at all") -> str:
    return (
        f"{check_id}:\n  check_name: P\n  severity: {severity}\n  risk: r\n  remediation: f\n"
        f"  articles:\n    - {{framework: POLICY, article: 'Policy ACME-7', title: '{title}'}}\n"
    )


def test_overlay_adds_new_check(tmp_path):
    overlay = _overlay(tmp_path, "o", _policy("CKV_AWS_999"))
    loaded = load_registry_with_overlays(default_registry_dir(), [overlay])
    assert "CKV_AWS_999" in loaded.mappings
    assert loaded.overridden == []
    assert loaded.overlay_files == [overlay / "extra.yaml"]


def test_overlay_overrides_bundled_severity(tmp_path):
    overlay = _overlay(tmp_path, "o", _policy("CKV_AWS_16"))
    loaded = load_registry_with_overlays(default_registry_dir(), [overlay])
    assert loaded.mappings["CKV_AWS_16"].severity == Severity.LOW
    assert loaded.overridden == ["CKV_AWS_16"]


def test_later_overlay_wins(tmp_path):
    first = _overlay(tmp_path, "a", _policy("CKV_AWS_999", "LOW"))
    second = _overlay(tmp_path, "b", _policy("CKV_AWS_999", "CRITICAL"))
    loaded = load_registry_with_overlays(default_registry_dir(), [first, second])
    assert loaded.mappings["CKV_AWS_999"].severity == Severity.CRITICAL


def test_overlay_policy_article_any_title(tmp_path):
    overlay = _overlay(tmp_path, "o", _policy("CKV_AWS_999", title="Custom ACME title"))
    mapping = load_registry_with_overlays(default_registry_dir(), [overlay]).mappings["CKV_AWS_999"]
    assert mapping.articles[0].title == "Custom ACME title"


def test_overlay_nis2_unknown_article_rejected(tmp_path):
    overlay = _overlay(tmp_path, "o", _entry("CKV_AWS_999", "Art. 99"))
    with pytest.raises(RegistryValidationError, match="not a known article"):
        load_registry_with_overlays(default_registry_dir(), [overlay])


def test_bundled_policy_titles_stay_strict(tmp_path):
    from tf_eu_guard.mapping.loader import load_registry_file

    path = tmp_path / "registry-x.yaml"
    path.write_text(_policy("CKV_AWS_999"), encoding="utf-8")
    with pytest.raises(RegistryValidationError):
        load_registry_file(path)


def test_overlay_dir_without_yaml_rejected(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError, match="no \\*.yaml") as excinfo:
        load_registry_with_overlays(default_registry_dir(), [tmp_path / "empty"])
    assert not isinstance(excinfo.value, RegistryValidationError)


@pytest.mark.parametrize("kind", ["missing", "empty"])
def test_bad_registry_dir_exits_2(monkeypatch, tmp_path, kind):
    directory = tmp_path / "d"
    if kind == "empty":
        directory.mkdir()
    fixture = str(Path(__file__).parent.parent / FIXTURE)
    code = run_cli(
        monkeypatch, tmp_path, "--checkov-json", fixture, "--registry-dir", str(directory)
    )
    assert code == 2


def test_registry_validate_missing_dir_exits_2(monkeypatch, tmp_path):
    assert run_command(monkeypatch, tmp_path, "registry", "validate", str(tmp_path / "nope")) == 2


def test_overlay_override_is_reported(monkeypatch, tmp_path, capsys):
    overlay = _overlay(tmp_path, "o", _policy("CKV_AWS_16"))
    code = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(Path(__file__).parent.parent / FIXTURE),
        "--registry-dir",
        str(overlay),
        "--output",
        "json",
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "Registry overlay loaded:" in err
    assert str(overlay) in err
    assert "1 override bundled checks" in err


def test_registry_validate_ok(monkeypatch, tmp_path, capsys):
    overlay = _overlay(tmp_path, "o", _policy("CKV_AWS_999") + _policy("CKV_AWS_998"))
    assert run_command(monkeypatch, tmp_path, "registry", "validate", str(overlay)) == 0
    out = capsys.readouterr().out
    assert "extra.yaml: 2 entries" in out
    assert "Total: 2 entries" in out


def test_registry_validate_bad_exits_3(monkeypatch, tmp_path):
    overlay = _overlay(tmp_path, "o", "CKV_AWS_999: [not, a, mapping]\n")
    assert run_command(monkeypatch, tmp_path, "registry", "validate", str(overlay)) == 3


def test_registry_validate_bundled_when_no_dir(monkeypatch, tmp_path, capsys):
    assert run_command(monkeypatch, tmp_path, "registry", "validate") == 0
    assert "registry-aws.yaml" in capsys.readouterr().out


def test_registry_unknown_subcommand_exits_2(monkeypatch, tmp_path, capsys):
    assert run_command(monkeypatch, tmp_path, "registry", "bogus") == 2
    assert "usage:" in capsys.readouterr().err
