"""Files changed since a Git ref, for ``--changed-since`` (N-05)."""

import os
import subprocess
from pathlib import Path

GIT_TIMEOUT = 10
_DIFF_FLAGS = ("--name-only", "-z", "--ignore-submodules=all", "--no-ext-diff", "--no-textconv")


def safe_git_argv(directory: Path, *argv: str) -> list[str]:
    """git argv with repo-config command execution (fsmonitor, hooks) disabled."""
    return [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(directory),
        *argv,
    ]


def safe_git_env(keep_index: bool = False) -> dict[str, str]:
    """Environment without ``GIT_*`` (GIT_DIR etc. redirect git); optionally keep the index."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") or (keep_index and k == "GIT_INDEX_FILE")
    }


def _git(repo: Path, *argv: str) -> str:
    try:
        done = subprocess.run(
            safe_git_argv(repo, *argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=safe_git_env(keep_index=True),
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(f"git {argv[0]} timed out after {GIT_TIMEOUT}s") from None
    except FileNotFoundError:
        raise ValueError("--changed-since needs git on PATH, but git was not found") from None
    if done.returncode != 0:
        raise ValueError(f"git {argv[0]} failed: {done.stderr.strip()}")
    return done.stdout


_TF_SUFFIXES = (".tf", ".tfvars", ".hcl")


def in_changed_scope(path: Path, changed: set[Path], iac_type: str) -> bool:
    """Whether a finding in ``path`` is affected by the changed files (all resolved, absolute).

    Terraform is evaluated per module directory, so a changed Terraform file widens the scope to
    its directory, that directory's parents and its subdirectories. Sibling modules reached
    through ``../`` sources are not followed. Other IaC types are file-granular.
    """
    if path in changed:
        return True
    if iac_type != "terraform":
        return False
    here = path.parent
    return any(
        c.name.endswith(_TF_SUFFIXES)
        and (c.parent == here or c.parent in here.parents or here in c.parent.parents)
        for c in changed
    )


def changed_files(repo_root: Path, ref: str) -> set[Path]:
    """Resolved paths changed in ``REF...HEAD`` or staged in the index.

    Unstaged and untracked changes are not included: comparing the working tree can
    run repo-configured filter drivers. Raises ``ValueError`` for a ref that
    looks like an option, an unknown ref, a missing git, or a non-repository.
    """
    if ref.startswith("-"):
        raise ValueError(f"--changed-since ref must not start with '-': {ref!r}")
    try:
        top = Path(_git(repo_root, "rev-parse", "--show-toplevel").strip())
    except ValueError as error:
        if "git was not found" in str(error):
            raise
        raise ValueError(f"--changed-since needs a Git repository at {repo_root}") from None
    try:
        outputs = [
            _git(top, "diff", *_DIFF_FLAGS, f"{ref}...HEAD", "--"),
            _git(top, "diff", *_DIFF_FLAGS, "--cached", "--"),
        ]
    except ValueError as error:
        raise ValueError(f"--changed-since: unknown ref {ref!r} ({error})") from None
    return {(top / name).resolve() for out in outputs for name in out.split("\0") if name}
