"""Checkov subprocess execution and scan-root validation."""

import json
import os
import re
import subprocess
import sys
import sysconfig
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from tf_eu_guard.checkov.json import validate_scan_output
from tf_eu_guard.checkov.types import CheckovRuntimeError
from tf_eu_guard.constants import DEFAULT_CHECKOV_TIMEOUT, SUPPORTED_IAC_TYPES
from tf_eu_guard.reporting.untrusted import sanitize
from tf_eu_guard.residency import RESIDENCY_ENV_VARS


def stderr_tail(stderr: str | None, limit: int = 20) -> str:
    """Return the final stderr lines, keeping runtime errors actionable."""
    lines = (stderr or "").splitlines()
    return "\n".join(lines[-limit:]) or "(no stderr output)"


CHECKOV_CONFIG_ENV_VARS = (
    "CKV_CHECK",
    "CKV_EVAL_VARS",
    "CKV_EXTERNAL_CHECKS_PUBLIC_KEY",
    "CKV_FRAMEWORK",
    "CKV_NO_FAIL_ON_CRASH",
    "CKV_POLICY_METADATA_FILTER",
    "CKV_POLICY_METADATA_FILTER_EXCEPTION",
    "CKV_SECRETS_SCAN_BLOCK_LIST",
    "CKV_SECRETS_SCAN_ENABLE_ALL",
    "CKV_SECRETS_SCAN_FILE_TYPE",
    "CKV_SKIP_CHECK",
    "CKV_SKIP_RESOURCES_WITHOUT_VIOLATIONS",
    "CKV_VAR_FILE",
    "DOWNLOAD_EXTERNAL_MODULES",
    "EXTERNAL_MODULES_DIR",
    "LOG_LEVEL",
)

# Whole families of variables are removed: ``BC_*`` / ``PRISMA_*`` switch
# Checkov into platform mode (results are uploaded and platform-side
# suppressions apply), and ``CKV_IGNORE*`` change which directories are scanned.
CHECKOV_ENV_PREFIXES = ("BC_", "PRISMA_", "CKV_IGNORE")


CHECKOV_BOOTSTRAP = """
import sys

import checkov.common.util.config_utils as config_utils
import checkov.main as checkov_main


# Checkov 3.3.x discovers .checkov.yml/.checkov.yaml from the scan directory,
# cwd, and HOME. tf-eu-guard owns the checks that are required for its report,
# so user configuration must not be able to remove them silently.
config_utils.get_default_config_paths = lambda argv: []
checkov_main.get_default_config_paths = lambda argv: []

sys.exit(checkov_main.Checkov(sys.argv[1:]).run())
"""


def _drive(path: Path) -> str:
    """Return the case-folded drive of *path* ('' on POSIX)."""
    return os.path.splitdrive(str(path.resolve()))[0].casefold()


def trusted_checkov_workdir(target: Path) -> Path:
    """Return a directory outside the scanned checkout for Checkov's cwd.

    Checkov calls ``os.path.relpath`` against its cwd, which raises on Windows
    when the cwd and the scanned files are on different drives. The default is
    the package's own ``site-packages`` (or package directory); when that is on
    another drive than *target*, the root of the target's drive is used. A drive
    root is not controlled by the checkout, and no directory inside the target
    is ever returned. ``-I`` below and the patched config discovery prevent a
    cwd from shadowing Checkov or injecting configuration.
    """
    purelib = Path(sysconfig.get_path("purelib"))
    # This fallback is still package-relative and, unlike the scan target, is
    # controlled by tf-eu-guard.
    default = purelib if purelib.is_dir() else Path(__file__).resolve().parent
    if _drive(default) == _drive(target):
        return default
    drive = os.path.splitdrive(str(target.resolve()))[0]
    return Path(drive + os.sep)


def checkov_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an environment without Checkov's user-configurable scan filters.

    The residency-policy variables are dropped from the ambient environment
    too, so only the values passed explicitly in *extra* reach the checks. ``GIT_*``
    is dropped as well so Checkov's git clones cannot be redirected.
    """
    environment = os.environ.copy()
    scrubbed = {*CHECKOV_CONFIG_ENV_VARS, *RESIDENCY_ENV_VARS}
    for name in list(environment):
        if name in scrubbed or name.startswith((*CHECKOV_ENV_PREFIXES, "GIT_")):
            del environment[name]
    if extra:
        environment.update(extra)
    return environment


# Directories Checkov never descends into. Mirrors Checkov 3.3.x
# ``checkov.common.runners.base_runner`` (default of ``CKV_IGNORED_DIRECTORIES``,
# matched on the entry's base name) plus its hidden-name rule (any entry whose
# name starts with '.'). Defined here rather than imported because Checkov
# evaluates the environment variable at import time, and a user value must not
# change what these guards consider "scanned".
CHECKOV_IGNORED_DIRECTORIES = ("node_modules", ".terraform", ".serverless")

#: File suffixes Checkov reads per IaC type (symlink checks only matter for these).
SOURCE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "terraform": (".tf", ".tfvars", ".hcl"),
    "kubernetes": (".yaml", ".yml", ".json"),
}


def _compile_exclude_patterns(excludes: Sequence[str]) -> list[re.Pattern[str]]:
    """Compile ``--exclude`` values exactly as Checkov compiles ``--skip-path``."""
    compiled: list[re.Pattern[str]] = []
    for pattern in excludes:
        try:
            compiled.append(
                re.compile(re.escape(pattern) if re.match(r"^\.[^\.]", pattern) else pattern)
            )
        except re.error:
            continue  # Checkov still applies the plain substring test below
    return compiled


def _is_excluded(directory: str, name: str, excludes: Sequence[str]) -> bool:
    """Return whether an ``--exclude`` pattern matches entry *name* of *directory*."""
    if not excludes:
        return False
    full_path = os.path.join(directory, name)
    return any(p.search(full_path) for p in _compile_exclude_patterns(excludes)) or any(
        p in full_path for p in excludes
    )


def _is_skipped(directory: str, name: str, excludes: Sequence[str]) -> bool:
    """Return whether Checkov would skip entry *name* of *directory*."""
    if name in CHECKOV_IGNORED_DIRECTORIES or name.startswith("."):
        return True
    return _is_excluded(directory, name, excludes)


# Hidden directories that hold tooling, not infrastructure source.
_TOOLING_DIRECTORIES = frozenset(
    {
        ".git",
        ".github",
        ".gitlab",
        ".terraform",
        ".venv",
        ".tox",
        ".cache",
        ".vscode",
        ".idea",
        ".devcontainer",
        ".husky",
        ".terragrunt-cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".circleci",
    }
)


def _has_source_file(
    directory: Path, suffixes: tuple[str, ...], excludes: Sequence[str] = ()
) -> bool:
    """Return whether *directory* holds a source file, pruned like Checkov's own walk."""
    for current, dirs, files in os.walk(directory):
        dirs[:] = [
            d
            for d in dirs
            if d not in CHECKOV_IGNORED_DIRECTORIES
            and d not in _TOOLING_DIRECTORIES
            and not _is_excluded(current, d, excludes)
        ]
        if any(f.lower().endswith(suffixes) for f in files):
            return True
    return False


def hidden_source_dirs(root: Path, iac_type: str, excludes: Sequence[str] = ()) -> list[Path]:
    """Return top-most hidden directories under *root* that hold files Checkov skips."""
    suffixes = SOURCE_SUFFIXES.get(iac_type, ())
    if not suffixes:
        return []
    found: list[Path] = []
    for current, dirs, _files in os.walk(root):
        keep: list[str] = []
        for name in sorted(dirs):
            if name.startswith("."):
                path = Path(current) / name
                if (
                    name not in _TOOLING_DIRECTORIES
                    and not path.is_symlink()
                    and not _is_excluded(current, name, excludes)
                    and _has_source_file(path, suffixes, excludes)
                ):
                    found.append(path)
            elif not _is_skipped(current, name, excludes):
                keep.append(name)
        dirs[:] = keep
    return sorted(found)


def hidden_dirs_warning(found: Sequence[Path], iac_type: str, limit: int = 5) -> str:
    """Format the stderr warning for :func:`hidden_source_dirs` results."""
    suffixes = ", ".join(SOURCE_SUFFIXES[iac_type])
    listed = ", ".join(sanitize(path) for path in found[:limit])
    if len(found) > limit:
        listed += f", ... and {len(found) - limit} more"
    noun = "directory contains" if len(found) == 1 else "directories contain"
    return (
        f"Warning: not scanned: {len(found)} hidden {noun} {suffixes} files that Checkov "
        f"skips: {listed}. Pass such a directory as the scan path to scan it."
    )


def iter_scanned_files(root: Path, excludes: Sequence[str] = ()) -> Iterator[Path]:
    """Yield the files under *root* that Checkov would consider (no link following)."""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not _is_skipped(current, d, excludes))
        for name in sorted(files):
            if not _is_skipped(current, name, excludes):
                yield Path(current) / name


def reject_unsupported_source_files(
    target: Path, iac_type: str, excludes: Sequence[str] = ()
) -> None:
    """Reject source formats that Checkov silently ignores for this framework."""
    if iac_type != "terraform":
        return
    json_sources = [
        path for path in iter_scanned_files(target, excludes) if path.name.endswith(".tf.json")
    ]
    if json_sources:
        names = ", ".join(str(path) for path in json_sources[:5])
        if len(json_sources) > 5:
            names += f", ... and {len(json_sources) - 5} more"
        raise ValueError(
            "Terraform JSON source files (*.tf.json) are not supported by "
            f"Checkov's {iac_type} source framework: {names}. Convert the "
            "configuration to .tf HCL, scan a Terraform plan JSON with "
            "--iac-type terraform_plan, or skip them with --exclude."
        )


def is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is inside *root*, including the root itself."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate_scan_root_symlinks(
    scan_root: Path,
    iac_type: str = "terraform",
    excludes: Sequence[str] = (),
) -> list[str]:
    """Reject unsafe links in the part of the tree Checkov reads.

    Directories Checkov skips (hidden, ``.terraform``, ``node_modules``, and
    ``--exclude`` matches) are not inspected. A link that is broken or escapes
    the resolved root raises :class:`ValueError` when it is a directory that
    would be walked or a file Checkov would parse for *iac_type*. Other
    escaping or broken links are returned as warning strings.
    """
    root = scan_root.resolve(strict=True)
    suffixes = SOURCE_SUFFIXES.get(iac_type, ())
    pending = [root]
    visited: set[Path] = set()
    warnings: list[str] = []

    while pending:
        current = pending.pop().resolve(strict=True)
        if current in visited:
            continue
        visited.add(current)

        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            raise ValueError(
                f"Cannot inspect scan root '{current}' while validating symlinks: {exc}"
            ) from exc

        for entry in entries:
            if _is_skipped(str(current), entry.name, excludes):
                continue
            candidate = Path(entry.path)
            if entry.is_symlink():
                relevant = candidate.name.lower().endswith(suffixes)
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    if relevant:
                        raise ValueError(
                            f"Symlink '{candidate}' is broken or cannot be resolved"
                        ) from exc
                    warnings.append(f"broken symlink '{candidate}' (not a file Checkov reads)")
                    continue
                escapes = not is_within(resolved, root)
                if escapes and (resolved.is_dir() or relevant):
                    raise ValueError(
                        f"Symlink '{candidate}' resolves outside scan root '{root}' to '{resolved}'"
                    )
                if escapes:
                    warnings.append(
                        f"symlink '{candidate}' resolves outside scan root to '{resolved}' "
                        "(not a file Checkov reads for this IaC type)"
                    )
                elif resolved.is_dir():
                    pending.append(resolved)
            elif entry.is_dir(follow_symlinks=False):
                pending.append(candidate)
    return warnings


def find_remote_modules(target: Path, excludes: Sequence[str] = ()) -> list[tuple[Path, str, str]]:
    """Return ``(file, module name, source)`` for module calls with a non-local source."""
    try:
        import hcl2
    except ImportError:  # pragma: no cover - hcl2 is a Checkov dependency
        return []

    found: list[tuple[Path, str, str]] = []
    for path in iter_scanned_files(target, excludes):
        if path.suffix != ".tf" or not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                parsed = hcl2.load(handle)
        except Exception:  # noqa: BLE001 - parse problems are Checkov's to report
            continue
        for block in parsed.get("module", []):
            for name, body in block.items():
                source = body.get("source") if isinstance(body, dict) else None
                if isinstance(source, list):
                    source = source[0] if source else None
                if not isinstance(source, str):
                    continue
                source = source.strip().strip('"')
                if not source.startswith(("./", "../")):
                    found.append((path, str(name).strip('"'), source))
    return found


def remote_modules_warning(modules: Sequence[tuple[Path, str, str]], limit: int = 10) -> str:
    """Format the stderr warning for :func:`find_remote_modules` results."""
    listed = "; ".join(
        f"module.{sanitize(name)} ({sanitize(source)}) in {sanitize(path)}"
        for path, name, source in modules[:limit]
    )
    if len(modules) > limit:
        listed += f"; ... and {len(modules) - limit} more"
    return (
        "Warning: not analysed: remote module sources. Checkov does not download "
        "modules, so resources defined inside these modules were never evaluated "
        f"and no findings are reported for them: {listed}"
    )


def run_checkov(
    target: Path,
    iac_type: str = "terraform",
    residency_env: Mapping[str, str] | None = None,
    exclude: Sequence[str] = (),
    online: bool = False,
    timeout: float | None = DEFAULT_CHECKOV_TIMEOUT,
    var_files: Sequence[Path] = (),
    download_external_modules: bool = False,
    secrets: bool = False,
) -> dict[str, Any]:
    """Run Checkov against a directory or plan file and return parsed JSON.

    *residency_env* carries the residency-policy variables for the custom
    checks (see :mod:`tf_eu_guard.residency`); without it the checks default
    to ``eu-eea``.

    *exclude* patterns are passed to Checkov as ``--skip-path`` and honoured by
    the pre-scan guards. Checkov is run with ``--skip-download`` (no call to
    the Prisma Cloud platform for guideline metadata) unless *online* is set;
    platform API keys are removed from its environment in both modes.

    *timeout* (seconds, default 600; ``0`` or ``None`` disables) bounds the
    Checkov subprocess; exceeding it raises :class:`CheckovRuntimeError`.

    *var_files* are passed as ``--var-file`` (Terraform variable definitions);
    *download_external_modules* lets Checkov fetch registry and Git modules
    (network access, third-party code).

    *secrets* adds Checkov's ``secrets`` framework; its results are merged into
    the *iac_type* result and never carry secret values (see
    :func:`tf_eu_guard.checkov.json.normalize_checkov_output`).
    """
    if iac_type not in SUPPORTED_IAC_TYPES:
        raise ValueError(
            f"Unsupported iac_type '{iac_type}' — expected one of {', '.join(SUPPORTED_IAC_TYPES)}"
        )
    target = Path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    resolved_vars = [Path(v).resolve() for v in var_files]
    for var_file in resolved_vars:
        if not var_file.is_file():
            raise ValueError(f"var file does not exist or is not a file: {var_file}")

    # The custom EU-compliance checks live beside the runner package.
    checks_dir = Path(__file__).resolve().parent.parent / "checks"

    if iac_type == "terraform_plan":
        if not target.is_file():
            raise ValueError(
                f"terraform_plan requires a plan file (terraform show -json "
                f"output), but '{target}' is not a file"
            )
        target_flag = ["-f", str(target)]
    else:
        if not target.is_dir():
            raise ValueError(
                f"iac_type '{iac_type}' scans a directory, but '{target}' is not a directory"
            )
        for warning in validate_scan_root_symlinks(target, iac_type, exclude):
            print(f"Warning: {sanitize(warning)}", file=sys.stderr)
        reject_unsupported_source_files(target, iac_type, exclude)
        target_flag = ["-d", str(target)]

    cmd = [
        sys.executable,
        "-I",
        "-c",
        CHECKOV_BOOTSTRAP,
        *target_flag,
        "--external-checks-dir",
        str(checks_dir),
        "--output",
        "json",
        "--framework",
        iac_type,
        *(["secrets"] if secrets else []),
    ]
    if not online:
        cmd.append("--skip-download")
    for pattern in exclude:
        cmd.extend(["--skip-path", pattern])
    for var_file in resolved_vars:
        cmd.extend(["--var-file", str(var_file)])
    if download_external_modules:
        cmd.extend(["--download-external-modules", "true"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            cwd=trusted_checkov_workdir(target),
            env=checkov_environment(residency_env),
            timeout=timeout or None,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckovRuntimeError(
            f"Checkov did not finish within {timeout:g} seconds and was stopped. "
            "Scan a smaller path, use --exclude, or raise the limit with "
            "--timeout SECONDS (0 disables it)."
        ) from exc

    if result.returncode not in (0, 1):
        raise CheckovRuntimeError(
            f"Checkov exited with status {result.returncode}. "
            f"Last stderr lines:\n{stderr_tail(result.stderr)}"
        )

    try:
        checkov_output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckovRuntimeError(
            f"Checkov returned invalid JSON: {exc}. "
            f"Last stderr lines:\n{stderr_tail(result.stderr)}"
        ) from exc

    validated = validate_scan_output(checkov_output, iac_type, ("secrets",) if secrets else ())
    if download_external_modules:
        print(
            "Note: --download-external-modules fetched third-party module code "
            "from the network; the modules' resources were evaluated.",
            file=sys.stderr,
        )
    elif iac_type == "terraform":
        remote = find_remote_modules(target, exclude)
        if remote:
            print(remote_modules_warning(remote), file=sys.stderr)
    if iac_type in ("terraform", "kubernetes"):
        hidden = hidden_source_dirs(target, iac_type, exclude)
        if hidden:
            print(hidden_dirs_warning(hidden, iac_type), file=sys.stderr)
    return validated
