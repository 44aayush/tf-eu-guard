"""Integration tests for the shipped pre-commit hook (.pre-commit-hooks.yaml).

The hook previously broke every commit that touched a ``.tf`` file: pre-commit
appended each matched file as a positional argument after
``tf-eu-guard scan`` and the CLI rejected the invocation
(``error: unrecognized arguments``). The fix is ``pass_filenames: false`` plus
a CLI default of the current working directory — these tests lock both in.

Structure:

- A *hermetic* test parses the hook definition and asserts the wiring
  (``pass_filenames: false``, entry, args) — runs everywhere, no git needed.
- An *integration* test builds a throwaway git repository whose
  ``.pre-commit-config.yaml`` references a temporary hook repo containing the
  exact ``.pre-commit-hooks.yaml`` from the working tree, then runs
  ``pre-commit run --all-files``:

  - the vulnerable fixture must exit non-zero (findings gate the commit),
  - the compliant fixture must exit zero.

  The hook's ``language`` is overridden to ``system`` (with the running
  interpreter's bin dir prepended to PATH) so pre-commit doesn't build an
  isolated environment — everything else (entry, args, ``files``,
  ``pass_filenames``) comes from the shipped definition. Skipped when
  ``pre-commit`` or git isn't available.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HOOK_FILE = ".pre-commit-hooks.yaml"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _bin_available(name: str) -> bool:
    """A binary is usable if it's on PATH or beside the running interpreter."""
    return (
        shutil.which(name) is not None
        or (Path(sys.executable).parent / name).exists()
    )


# Only the subprocess-based integration tests are conditional; the hermetic
# wiring test below always runs.
integration_skip = pytest.mark.skipif(
    not (_bin_available("pre-commit") and _bin_available("tf-eu-guard")
         and shutil.which("git") is not None),
    reason="pre-commit / git / tf-eu-guard not available for the hook integration test",
)


def test_hook_definition_wiring(repo_root: Path):
    """Hermetic: the shipped hook must not receive filenames (TASKS.md P0 #1).

    Runs even when pre-commit isn't installed, so the pass_filenames fix can't
    regress unnoticed.
    """
    hook = yaml.safe_load((repo_root / HOOK_FILE).read_text())
    assert isinstance(hook, list) and len(hook) == 1
    entry = hook[0]
    assert entry["id"] == "tf-eu-guard"
    # The linchpin: without this, pre-commit appends every matched .tf file as
    # a positional argument and the CLI errors out.
    assert entry["pass_filenames"] is False
    # The entry + args must be exactly what the CLI can parse with no path.
    assert entry["entry"] == "tf-eu-guard scan"
    assert entry["args"] == ["--output", "dev", "--fail-on-severity", "HIGH"]


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")


def _commit_all(repo: Path) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fixture")
    return _git(repo, "rev-parse", "HEAD")


def _make_hook_repo(tmp_path: Path, repo_root: Path) -> tuple[Path, str]:
    """A disposable git repo carrying the working tree's hook definition.

    Referencing the tf-eu-guard checkout directly would test the last *commit*,
    not the working tree; copying the definition into a fresh repo keeps the
    test honest about uncommitted changes too.
    """
    hook_repo = tmp_path / "hook-repo"
    _init_repo(hook_repo)
    shutil.copy(repo_root / HOOK_FILE, hook_repo / HOOK_FILE)
    return hook_repo, _commit_all(hook_repo)


def _make_fixture_repo(
    tmp_path: Path, name: str, example: str, hook_repo: Path, hook_rev: str
) -> Path:
    repo = tmp_path / name
    _init_repo(repo)
    src = REPO_ROOT / "examples" / example
    for f in sorted(src.iterdir()):
        if f.is_file():
            shutil.copy(f, repo / f.name)
    (repo / ".pre-commit-config.yaml").write_text(
        f"repos:\n"
        f"  - repo: {hook_repo.as_uri()}\n"
        f"    rev: {hook_rev}\n"
        f"    hooks:\n"
        f"      - id: tf-eu-guard\n"
        f"        language: system  # use the interpreter already on PATH\n"
    )
    _commit_all(repo)
    return repo


def _run_precommit(repo: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Make the running interpreter's scripts (incl. tf-eu-guard) resolvable by
    # the language: system hook.
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"
    env.setdefault("HOME", str(Path.home()))
    return subprocess.run(
        ["pre-commit", "run", "--all-files"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


@pytest.fixture(scope="module")
def hook_repo(tmp_path_factory) -> tuple[Path, str]:
    return _make_hook_repo(tmp_path_factory.mktemp("precommit"), REPO_ROOT)


@integration_skip
def test_precommit_hook_gates_vulnerable_fixture(tmp_path, hook_repo):
    """pre-commit run --all-files must exit non-zero on known-vulnerable .tf."""
    hook_path, hook_rev = hook_repo
    repo = _make_fixture_repo(tmp_path, "vulnerable", "vulnerable-aws", hook_path, hook_rev)
    result = _run_precommit(repo)
    assert "tf-eu-guard" in result.stdout + result.stderr, (
        "hook did not run — check the files: pattern and pre-commit output:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert result.returncode != 0, (
        "vulnerable fixture must fail the hook:\n"
        f"{result.stdout}\n{result.stderr}"
    )


@integration_skip
def test_precommit_hook_passes_compliant_fixture(tmp_path, hook_repo):
    """pre-commit run --all-files must exit zero on the compliant fixture."""
    hook_path, hook_rev = hook_repo
    repo = _make_fixture_repo(tmp_path, "compliant", "compliant-aws", hook_path, hook_rev)
    result = _run_precommit(repo)
    assert result.returncode == 0, (
        "compliant fixture must pass the hook:\n"
        f"{result.stdout}\n{result.stderr}"
    )
