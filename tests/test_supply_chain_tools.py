"""Tests for the supply-chain gate tools run in CI (SBOM lock and dependency exceptions)."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sbom_lock = _load("check_sbom_lock")
dep_exc = _load("check_dependency_exceptions")


# --- check_sbom_lock -------------------------------------------------------


def _run_sbom(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, lock: str, components: list[dict[str, str]]
) -> int:
    lock_file = tmp_path / "requirements.lock"
    lock_file.write_text(lock, encoding="utf-8")
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps({"components": components}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_sbom_lock.py", str(lock_file), str(sbom_file)])
    return int(sbom_lock.main())


def test_sbom_lock_match_returns_0(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = "foo==1.0 \\\n    --hash=sha256:abc\n"
    assert _run_sbom(monkeypatch, tmp_path, lock, [{"name": "foo", "version": "1.0"}]) == 0
    assert "same 1 components" in capsys.readouterr().out


def test_sbom_lock_mismatch_returns_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = "foo==1.0\nbar==2.0\nbaz==3.0\n"
    components = [
        {"name": "foo", "version": "1.1"},
        {"name": "bar", "version": "2.0"},
        {"name": "extra", "version": "9"},
    ]
    assert _run_sbom(monkeypatch, tmp_path, lock, components) == 1
    err = capsys.readouterr().err
    assert "missing locked components" in err
    assert "('baz', '3.0')" in err
    assert "('foo', '1.0')" in err
    assert "absent from lock" in err
    assert "('extra', '9')" in err
    assert "('foo', '1.1')" in err


def test_sbom_lock_missing_only_reports_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_sbom(monkeypatch, tmp_path, "foo==1.0\n", []) == 1
    err = capsys.readouterr().err
    assert "missing locked components" in err
    assert "absent from lock" not in err


def test_sbom_lock_usage_returns_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["check_sbom_lock.py", "only-one"])
    assert sbom_lock.main() == 2
    assert "usage:" in capsys.readouterr().err


def test_sbom_lock_normalises_names(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert (
        _run_sbom(monkeypatch, tmp_path, "Foo_Bar==1.0\n", [{"name": "foo-bar", "version": "1.0"}])
        == 0
    )


# --- check_dependency_exceptions -------------------------------------------


def _exception(**overrides: Any) -> dict[str, Any]:
    today = date.today()
    base: dict[str, Any] = {
        "advisory": "GHSA-aaaa-bbbb-cccc",
        "owner": "someone",
        "package": "Foo_Bar",
        "locked_version": "1.0",
        "introduced_by": "baz",
        "rationale": "r",
        "mitigation": "m",
        "reachability": "none",
        "review_date": (today - timedelta(days=1)).isoformat(),
        "expiry_date": (today + timedelta(days=30)).isoformat(),
    }
    base.update(overrides)
    return base


def _run_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    data: Any,
    *,
    lock: str = "foo-bar==1.0 \\\n    --hash=sha256:abc\n",
    workflow: str = "pip-audit --ignore-vuln GHSA-aaaa-bbbb-cccc\n",
) -> int:
    exceptions = tmp_path / "dependency-exceptions.json"
    exceptions.write_text(json.dumps(data), encoding="utf-8")
    lock_path = tmp_path / "requirements.lock"
    lock_path.write_text(lock, encoding="utf-8")
    workflow_path = tmp_path / "ci.yml"
    workflow_path.write_text(workflow, encoding="utf-8")
    monkeypatch.setattr(dep_exc, "EXCEPTIONS_PATH", exceptions)
    monkeypatch.setattr(dep_exc, "LOCK_PATH", lock_path)
    monkeypatch.setattr(dep_exc, "WORKFLOW_PATH", workflow_path)
    return int(dep_exc.main())


def _valid(**top: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"owner": "team", "exceptions": [_exception()]}
    data.update(top)
    return data


def test_dependency_exceptions_valid_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid()) == 0
    assert "OK: 1 dependency advisory exceptions valid" in capsys.readouterr().out


def test_dependency_exceptions_missing_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid(owner="")) == 1
    assert "top-level owner is required" in capsys.readouterr().err


@pytest.mark.parametrize("value", [[], "nope", None])
def test_dependency_exceptions_empty_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], value: Any
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid(exceptions=value), workflow="") == 1
    assert "exceptions must be a non-empty list" in capsys.readouterr().err


def test_dependency_exceptions_not_an_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid(exceptions=["x"]), workflow="") == 1
    assert "exception 1 must be an object" in capsys.readouterr().err


def test_dependency_exceptions_missing_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    entry = _exception()
    del entry["mitigation"]
    del entry["expiry_date"]
    assert _run_exceptions(monkeypatch, tmp_path, _valid(exceptions=[entry]), workflow="") == 1
    assert "exception 1 missing: expiry_date, mitigation" in capsys.readouterr().err


def test_dependency_exceptions_duplicate_advisory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _valid(exceptions=[_exception(), _exception()])
    assert _run_exceptions(monkeypatch, tmp_path, data) == 1
    assert "duplicate advisory GHSA-aaaa-bbbb-cccc" in capsys.readouterr().err


def test_dependency_exceptions_lock_version_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid(), lock="foo-bar==2.0\n") == 1
    assert "foo-bar lock is '2.0', expected '1.0'" in capsys.readouterr().err


def test_dependency_exceptions_package_not_locked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_exceptions(monkeypatch, tmp_path, _valid(), lock="other==1.0\n") == 1
    assert "foo-bar lock is None, expected '1.0'" in capsys.readouterr().err


def test_dependency_exceptions_invalid_date(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _valid(exceptions=[_exception(review_date="not-a-date")])
    assert _run_exceptions(monkeypatch, tmp_path, data) == 1
    assert "invalid review/expiry date" in capsys.readouterr().err


def test_dependency_exceptions_review_after_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    future = date.today() + timedelta(days=10)
    data = _valid(
        exceptions=[
            _exception(
                review_date=(future + timedelta(days=5)).isoformat(), expiry_date=future.isoformat()
            )
        ]
    )
    assert _run_exceptions(monkeypatch, tmp_path, data) == 1
    assert "review_date must not be after expiry_date" in capsys.readouterr().err


def test_dependency_exceptions_expired(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    today = date.today()
    data = _valid(
        exceptions=[
            _exception(
                review_date=(today - timedelta(days=5)).isoformat(), expiry_date=today.isoformat()
            )
        ]
    )
    assert _run_exceptions(monkeypatch, tmp_path, data) == 1
    assert f"exception expired on {today.isoformat()}" in capsys.readouterr().err


def test_dependency_exceptions_workflow_ignore_list_differs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workflow = "pip-audit --ignore-vuln GHSA-aaaa-bbbb-cccc --ignore-vuln GHSA-zzzz\n"
    assert _run_exceptions(monkeypatch, tmp_path, _valid(), workflow=workflow) == 1
    assert "CI ignore list differs from dependency-exceptions.json" in capsys.readouterr().err
