"""Provenance data and the --evidence-dir bundle (N-15)."""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
from cli_helpers import FIXTURE, run_cli

from tf_eu_guard.provenance import git_commit, registry_digest

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "tf_eu_guard/schemas/report.schema.json").read_text())
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _abs(rel: str) -> str:
    return str(ROOT / rel)


def test_registry_digest_stable_and_order_independent(tmp_path):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    a.write_text("x", encoding="utf-8")
    b.write_text("y", encoding="utf-8")
    assert registry_digest([a, b]) == registry_digest([b, a])
    assert re.fullmatch(r"[0-9a-f]{64}", registry_digest([a, b]))


def test_registry_digest_changes_with_content(tmp_path):
    a = tmp_path / "a.yaml"
    a.write_text("x", encoding="utf-8")
    first = registry_digest([a])
    a.write_text("z", encoding="utf-8")
    assert registry_digest([a]) != first


def test_git_commit_none_outside_repo(tmp_path):
    assert git_commit(tmp_path) is None


def test_git_commit_none_without_git(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert git_commit(tmp_path) is None


@needs_git
def test_git_commit_has_no_dirty_suffix(tmp_path):
    def git(*a):
        subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *a],
            check=True,
            capture_output=True,
        )

    git("init")
    (tmp_path / "f.txt").write_text("1", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "x")
    clean = git_commit(tmp_path)
    assert clean and re.fullmatch(r"[0-9a-f]{40}", clean)
    (tmp_path / "f.txt").write_text("2", encoding="utf-8")
    assert git_commit(tmp_path / "f.txt") == clean  # no status: it can run filters


def test_json_object_has_provenance(monkeypatch, tmp_path, capsys):
    rc = run_cli(
        monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE),
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    assert rc in (0, 1)
    doc = json.loads(capsys.readouterr().out)
    jsonschema.validate(doc, SCHEMA)
    prov = doc["provenance"]
    assert re.fullmatch(r"[0-9a-f]{64}", prov["registry_sha256"])
    assert prov["tool_version"] and "registry-aws.yaml" in prov["registry_files"]
    assert set(prov["checks"]) == {"passed", "failed", "skipped"}
    assert prov["options"]["output"] == "json"
    assert "command" not in prov["options"] and None not in prov["options"].values()


def test_auditor_report_has_escaped_provenance(monkeypatch, tmp_path):
    out = tmp_path / "a.html"
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE),
        "--output", "auditor", "--output-file", str(out),
    )  # fmt: skip
    html = out.read_text(encoding="utf-8")
    assert "Provenance" in html and "Registry SHA-256" in html


def test_evidence_dir_manifest_hashes_match(monkeypatch, tmp_path, capsys):
    ev = tmp_path / "deep" / "ev"
    run_cli(monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE), "--evidence-dir", str(ev))
    manifest = json.loads((ev / "manifest.json").read_text(encoding="utf-8"))
    names = {
        "dev.html",
        "security.html",
        "auditor.html",
        "report.json",
        "report.sarif",
        "summary.md",
    }
    assert set(manifest["files"]) == names
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((ev / name).read_bytes()).hexdigest() == digest
    assert manifest["created"].endswith("Z") and manifest["provenance"]["registry_sha256"]
    report = json.loads((ev / "report.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, SCHEMA)
    assert report["provenance"] == manifest["provenance"]


def test_evidence_dir_refuses_non_empty(monkeypatch, tmp_path, capsys):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "x").write_text("1", encoding="utf-8")
    assert (
        run_cli(monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE), "--evidence-dir", str(ev))
        == 2
    )
    assert (ev / "x").read_text(encoding="utf-8") == "1"
    f = tmp_path / "file"
    f.write_text("1", encoding="utf-8")
    assert (
        run_cli(monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE), "--evidence-dir", str(f))
        == 2
    )


def test_evidence_dir_allows_existing_empty_and_keeps_output(monkeypatch, tmp_path, capsys):
    ev = tmp_path / "ev"
    ev.mkdir()
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE),
        "--output", "json", "--evidence-dir", str(ev),
    )  # fmt: skip
    assert isinstance(json.loads(capsys.readouterr().out), list)
    assert (ev / "manifest.json").is_file()


def test_checkov_json_run_records_no_commit(monkeypatch, tmp_path, capsys):
    # The fixture sits inside this git repo; its commit must not be claimed as the scan's.
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE),
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    assert json.loads(capsys.readouterr().out)["provenance"]["commit"] is None


def test_secrets_merge_sums_checks_and_resources(monkeypatch, tmp_path, capsys):
    def element(kind, passed, failed, skipped, resources):
        summary = {
            "passed": passed, "failed": failed, "skipped": skipped,
            "resource_count": resources, "parsing_errors": 0, "checkov_version": "3.2.0",
        }  # fmt: skip
        return {
            "check_type": kind,
            "summary": summary,
            "results": {"passed_checks": [], "failed_checks": [], "skipped_checks": []},
        }

    doc = [element("terraform", 5, 2, 1, 7), element("secrets", 0, 3, "x", 4)]
    path = tmp_path / "c.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", str(path), "--secrets",
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    prov = json.loads(capsys.readouterr().out)["provenance"]
    assert prov["checks"] == {"passed": 5, "failed": 5, "skipped": 1}
    assert prov["resources_scanned"] == 11
    assert doc[0]["summary"]["failed"] == 2  # input not mutated


def _git_repo(tmp_path, marker):
    """A repo whose config runs ``touch marker`` whenever git consults fsmonitor."""
    repo = tmp_path / "repo"
    repo.mkdir()
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    (repo / "a.tf").write_text("a\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", *ident, "-C", str(repo), "commit", "-q", "-m", "x"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.fsmonitor", f"touch '{marker.as_posix()}'; false"],
        check=True,
        capture_output=True,
    )
    return repo


@needs_git
def test_git_commit_ignores_git_dir_env(tmp_path, monkeypatch):
    a, other = tmp_path / "a", tmp_path / "other"
    for repo, msg in ((a, "a"), (other, "o")):
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(repo)]
            + ["commit", "-q", "--allow-empty", "-m", msg],
            check=True,
            capture_output=True,
        )
    head = subprocess.run(
        ["git", "-C", str(a), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert (git_commit(a) or "").startswith(head)


@needs_git
def test_git_commit_does_not_run_repo_fsmonitor(tmp_path):
    marker = tmp_path / "PWNED"
    repo = _git_repo(tmp_path, marker)
    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True, check=False)
    assert marker.exists(), "fixture must be exploitable without the safe flags"
    marker.unlink()
    git_commit(repo)
    assert not marker.exists()


def test_git_timeout_returns_none(monkeypatch):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", 10)

    monkeypatch.setattr(subprocess, "run", boom)
    assert git_commit(Path(".")) is None


def test_dev_output_skips_provenance(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise AssertionError("git must not run for --output dev")

    monkeypatch.setattr("tf_eu_guard.provenance.git_commit", boom)
    assert run_cli(monkeypatch, tmp_path, "--checkov-json", _abs(FIXTURE), "--output", "dev") == 0


def test_needs_provenance_conditions():
    from argparse import Namespace

    from tf_eu_guard.provenance import needs_provenance

    base = {"evidence_dir": None, "output": "dev", "json_format": "array"}
    assert not needs_provenance(Namespace(**base))
    assert needs_provenance(Namespace(**{**base, "evidence_dir": "x"}))
    assert needs_provenance(Namespace(**{**base, "output": "auditor"}))
    assert needs_provenance(Namespace(**{**base, "output": "all"}))
    assert not needs_provenance(Namespace(**{**base, "output": "json"}))
    assert needs_provenance(Namespace(**{**base, "output": "json", "json_format": "object"}))


def _filter_repo(tmp_path, marker):
    """Repo with a racy index and a clean filter that runs when git compares content."""
    import os

    repo = tmp_path / "frepo"
    repo.mkdir()
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]

    def git(*a):
        subprocess.run(["git", *ident, "-C", str(repo), *a], check=True, capture_output=True)

    git("init", "-q")
    (repo / "a.tf").write_text("aaaa\n")
    (repo / ".gitattributes").write_text("* filter=evil\n")
    git("add", ".")
    git("commit", "-q", "-m", "x")
    git("config", "filter.evil.clean", f"touch '{marker.as_posix()}'; cat")
    (repo / "a.tf").write_text("bbbb\n")
    os.utime(repo / ".git" / "index", (1, 1))  # nonzero: git treats mtime 0 as "not racy"
    return repo


@needs_git
def test_git_commit_and_changed_files_do_not_run_filters(tmp_path):
    from tf_eu_guard.changed import changed_files

    marker = tmp_path / "PWNED"
    repo = _filter_repo(tmp_path, marker)
    subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True)
    assert marker.exists(), "fixture must be exploitable without the safe flags"
    marker.unlink()
    git_commit(repo)
    assert not marker.exists()
    changed_files(repo, "HEAD")
    assert not marker.exists()


def _provenance(path):
    from argparse import Namespace
    from types import SimpleNamespace

    from tf_eu_guard.provenance import build_provenance

    result = SimpleNamespace(registry=None, checkov_version=None)
    return build_provenance(Namespace(path=path), result, {})  # type: ignore[arg-type]


def test_commit_falls_back_to_env(tmp_path, monkeypatch):
    sha = "a" * 40
    monkeypatch.setenv("TF_EU_GUARD_COMMIT", sha)
    prov = _provenance(tmp_path)
    assert prov["commit"] == sha and prov["commit_source"] == "environment"


def test_commit_accepts_64_hex_sha256_object_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("TF_EU_GUARD_COMMIT", "b" * 64)
    assert _provenance(tmp_path)["commit"] == "b" * 64


@needs_git
def test_commit_prefers_git_over_env(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(tmp_path)]
        + ["commit", "-q", "--allow-empty", "-m", "x"],
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("TF_EU_GUARD_COMMIT", "a" * 40)
    prov = _provenance(tmp_path)
    assert prov["commit"] == git_commit(tmp_path) != "a" * 40
    assert prov["commit_source"] == "git"


@pytest.mark.parametrize("value", ["abc", "A" * 40, "g" * 40, "a" * 41, "a" * 40 + "\n", ""])
def test_commit_env_must_be_hex(tmp_path, monkeypatch, value):
    monkeypatch.setenv("TF_EU_GUARD_COMMIT", value)
    prov = _provenance(tmp_path)
    assert prov["commit"] is None and prov["commit_source"] is None


def test_commit_source_is_schema_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("TF_EU_GUARD_COMMIT", "a" * 40)
    prov = _provenance(tmp_path)
    prov["registry_sha256"] = "0" * 64
    jsonschema.validate(prov, SCHEMA["properties"]["provenance"])
