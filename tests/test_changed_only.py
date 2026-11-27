"""--changed-since REF: report only findings in files changed since a Git ref (N-05)."""

import json
import shutil
import subprocess

import pytest
from cli_helpers import run_cli

from tf_eu_guard.changed import changed_files, in_changed_scope

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "a.tf").write_text("a1\n")
    (tmp_path / "b.tf").write_text("b1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "one")
    _git(tmp_path, "tag", "base")
    (tmp_path / "a.tf").write_text("a2\n")
    _git(tmp_path, "commit", "-q", "-am", "two")
    return tmp_path


@pytest.fixture
def k8s_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "a.yaml").write_text("a1\n")
    (tmp_path / "b.yaml").write_text("b1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "one")
    _git(tmp_path, "tag", "base")
    (tmp_path / "a.yaml").write_text("a2\n")
    _git(tmp_path, "commit", "-q", "-am", "two")
    return tmp_path


def _check(check_id, path, resource):
    return {
        "check_id": check_id,
        "check_name": "n",
        "check_result": {"result": "FAILED"},
        "file_path": path,
        "file_line_range": [1, 2],
        "resource": resource,
    }


def test_changed_files_lists_committed_and_staged_not_unstaged(repo):
    (repo / "c.tf").write_text("c\n")
    _git(repo, "add", "c.tf")
    (repo / "b.tf").write_text("b2\n")  # unstaged: needs a worktree diff, which can run filters
    assert changed_files(repo, "base") == {(repo / n).resolve() for n in ("a.tf", "c.tf")}


def test_changed_files_handles_odd_names(repo):
    (repo / "my file.tf").write_text("x\n")
    _git(repo, "add", "my file.tf")
    assert (repo / "my file.tf").resolve() in changed_files(repo, "HEAD")


def test_changed_files_rejects_dash_ref(repo):
    with pytest.raises(ValueError, match="must not start with"):
        changed_files(repo, "--output=x")


def test_changed_files_unknown_ref_raises(repo):
    with pytest.raises(ValueError, match="nope"):
        changed_files(repo, "nope")


def test_changed_files_outside_repo_raises(tmp_path):
    with pytest.raises(ValueError, match="Git"):
        changed_files(tmp_path, "HEAD")


def test_changed_files_git_missing(repo, monkeypatch):
    monkeypatch.setattr("tf_eu_guard.changed.subprocess.run", _raise_missing)
    with pytest.raises(ValueError, match="git"):
        changed_files(repo, "HEAD")


def _raise_missing(*a, **k):
    raise FileNotFoundError


def test_changed_since_filters_findings(monkeypatch, k8s_repo, capsys):
    repo = k8s_repo
    doc = {
        "check_type": "kubernetes",
        "results": {
            "failed_checks": [
                _check("CKV_AWS_16", "/a.yaml", "aws_db_instance.a"),
                _check("CKV_AWS_16", "/b.yaml", "aws_db_instance.b"),
                _check("CKV_FAKE_1", "/b.yaml", "x.b"),
            ],
            "passed_checks": [],
            "skipped_checks": [],
        },
    }
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: doc)
    code = run_cli(
        monkeypatch, repo, str(repo), "--iac-type", "kubernetes", "--changed-since", "base",
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    cap = capsys.readouterr()
    assert code == 0
    out = json.loads(cap.out)
    assert [f["resource"] for f in out["findings"]] == ["aws_db_instance.a"]
    assert out["unmapped"] == []
    assert any(
        s.startswith("changed-since: base (1 changed file(s); 2 ")
        for s in out["scan"]["weakening_settings"]
    )
    assert (
        "Reporting only findings in 1 file(s) changed since base; "
        "2 finding(s) in unchanged files hidden" in cap.err
    )


def test_changed_since_with_checkov_json_exits_2(monkeypatch, tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"results": {"failed_checks": []}}))
    assert run_cli(monkeypatch, tmp_path, "--checkov-json", str(p), "--changed-since", "HEAD") == 2


def test_changed_since_with_plan_exits_2(monkeypatch, repo):
    (repo / "p.json").write_text("{}")
    args = (str(repo / "p.json"), "--iac-type", "terraform_plan", "--changed-since", "HEAD")
    assert run_cli(monkeypatch, repo, *args) == 2


def test_changed_since_bad_ref_exits_2(monkeypatch, repo):
    monkeypatch.setattr(
        "tf_eu_guard.checkov_runner.run_checkov",
        lambda *a, **k: {"results": {"failed_checks": []}},
    )
    assert run_cli(monkeypatch, repo, str(repo), "--changed-since", "nope") == 2


def test_changed_files_ref_matching_filename_is_not_a_pathspec(repo):
    (repo / "nope...HEAD").write_text("x\n")
    with pytest.raises(ValueError, match="nope"):
        changed_files(repo, "nope")


def test_changed_since_keeps_requirement_matrix(monkeypatch, k8s_repo, capsys):
    repo = k8s_repo
    doc = {
        "check_type": "kubernetes",
        "results": {
            "failed_checks": [_check("CKV_AWS_16", "/b.yaml", "aws_db_instance.b")],
            "passed_checks": [],
            "skipped_checks": [],
        },
    }
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: doc)

    def rows(*extra):
        run_cli(
            monkeypatch, repo, str(repo), "--iac-type", "kubernetes", "--output", "json",
            "--json-format", "object", *extra,
        )  # fmt: skip
        return json.loads(capsys.readouterr().out)

    plain, changed = rows(), rows("--changed-since", "base")
    assert changed["findings"] == [] and len(plain["findings"]) == 1
    assert changed["requirements"] == plain["requirements"]
    assert any(r.get("failed") or r.get("failing_checks") for r in plain["requirements"]), plain[
        "requirements"
    ][:2]


def test_changed_files_does_not_run_repo_fsmonitor(repo, tmp_path_factory):
    marker = tmp_path_factory.mktemp("marker") / "PWNED"
    _git(repo, "config", "core.fsmonitor", f"touch '{marker.as_posix()}'; false")
    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True, check=False)
    assert marker.exists(), "fixture must be exploitable without the safe flags"
    marker.unlink()
    changed_files(repo, "HEAD")
    assert not marker.exists()


def test_changed_files_timeout_fails_closed(repo, monkeypatch):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", 10)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(ValueError):
        changed_files(repo, "HEAD")


def test_changed_scope_same_directory(tmp_path):
    assert in_changed_scope(tmp_path / "rds.tf", {tmp_path / "variables.tf"}, "terraform") is True


def test_changed_scope_ancestor_and_descendant(tmp_path):
    nested = tmp_path / "modules/db/main.tf"
    assert in_changed_scope(nested, {tmp_path / "terraform.tfvars"}, "terraform") is True
    child_change = {tmp_path / "modules/db/variables.tf"}
    assert in_changed_scope(tmp_path / "main.tf", child_change, "terraform") is True


def test_changed_scope_unrelated_sibling_and_non_tf(tmp_path):
    path = tmp_path / "a/main.tf"
    assert in_changed_scope(path, {tmp_path / "b/main.tf"}, "terraform") is False
    assert in_changed_scope(path, {tmp_path / "README.md"}, "terraform") is False


def test_changed_scope_kubernetes_is_file_granular(tmp_path):
    assert in_changed_scope(tmp_path / "a.yaml", {tmp_path / "b.yaml"}, "kubernetes") is False


def test_changed_since_cross_file_change_keeps_finding(monkeypatch, tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "variables.tf").write_text("v1\n")
    (tmp_path / "rds.tf").write_text("r1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "one")
    _git(tmp_path, "tag", "base")
    (tmp_path / "variables.tf").write_text("v2\n")
    _git(tmp_path, "commit", "-q", "-am", "two")
    doc = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [_check("CKV_AWS_16", "/rds.tf", "aws_db_instance.a")],
            "passed_checks": [],
            "skipped_checks": [],
        },
    }
    monkeypatch.setattr("tf_eu_guard.checkov_runner.run_checkov", lambda *a, **k: doc)
    code = run_cli(
        monkeypatch, tmp_path, str(tmp_path), "--changed-since", "base",
        "--fail-on-severity", "HIGH",
    )  # fmt: skip
    assert code == 1
