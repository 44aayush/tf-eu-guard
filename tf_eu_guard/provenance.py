"""Provenance of a scan (N-15): what produced a report, and from which inputs."""

import argparse
import hashlib
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tf_eu_guard import __version__
from tf_eu_guard.changed import GIT_TIMEOUT, safe_git_argv, safe_git_env
from tf_eu_guard.json_layout import resolve_json_format

if TYPE_CHECKING:
    from tf_eu_guard.cli.pipeline import ScanFindings

# A full git object id (SHA-1 or SHA-256); the Action passes its GITHUB_SHA in this variable.
_COMMIT_ENV = "TF_EU_GUARD_COMMIT"
_COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")

# Arguments that are not scan options.
_NOT_OPTIONS = {"command", "evidence_dir"}


def registry_digest(files: Sequence[Path]) -> str:
    """sha256 over ``name NUL bytes NUL`` for each file, sorted by name."""
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda p: (p.name, str(p))):
        digest.update(path.name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def _git(directory: Path, *argv: str) -> str | None:
    try:
        done = subprocess.run(
            safe_git_argv(directory, *argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=safe_git_env(),
            timeout=GIT_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def git_commit(path: Path) -> str | None:
    """HEAD commit of the repository holding *path*; uncommitted changes are not detected.

    No ``git status``: comparing file contents can run repo-configured filter drivers.
    """
    try:
        directory = path if path.is_dir() else path.parent
        head = _git(directory, "rev-parse", "HEAD")
        return head.strip() if head is not None else None
    except Exception:  # never fail a scan over provenance
        return None


def _commit(path: Path | None) -> tuple[str | None, str | None]:
    """(commit, source): HEAD from git, else a well-formed TF_EU_GUARD_COMMIT, else none."""
    if not path:
        return None, None
    head = git_commit(path)
    if head:
        return head, "git"
    value = os.environ.get(_COMMIT_ENV, "")
    if _COMMIT_RE.fullmatch(value):
        return value, "environment"
    return None, None


def needs_provenance(args: argparse.Namespace) -> bool:
    """True when a requested output embeds provenance (so git need not run otherwise)."""
    return bool(
        getattr(args, "evidence_dir", None)
        or args.output in ("auditor", "all")
        or (args.output == "json" and resolve_json_format(args) == "object")
    )


def _plain(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def build_provenance(
    args: argparse.Namespace, result: "ScanFindings", checkov_output_summary: dict[str, Any]
) -> dict[str, Any]:
    """Provenance block for the JSON object, the auditor report and the manifest."""
    registry = result.registry
    files = registry.files if registry else []
    overlays = set(registry.overlay_files) if registry else set()
    options = {
        key: _plain(value)
        for key, value in sorted(vars(args).items())
        if key not in _NOT_OPTIONS and value is not None
    }
    if getattr(args, "output", None) == "json":
        options["json_format"] = resolve_json_format(args)
    summary = checkov_output_summary
    commit, commit_source = _commit(args.path)
    return {
        "tool_version": __version__,
        "checkov_version": result.checkov_version,
        "registry_sha256": registry_digest(files),
        "registry_files": [str(p) if p in overlays else p.name for p in files],
        "commit": commit,
        "commit_source": commit_source,
        "options": options,
        "resources_scanned": summary.get("resource_count"),
        "checks": {k: summary.get(k) for k in ("passed", "failed", "skipped")},
    }
