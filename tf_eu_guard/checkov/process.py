"""Checkov subprocess execution and scan-root validation."""

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

from tf_eu_guard.checkov.json import validate_scan_output
from tf_eu_guard.checkov.types import CheckovRuntimeError
from tf_eu_guard.constants import SUPPORTED_IAC_TYPES


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
)


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


def trusted_checkov_workdir() -> Path:
    """Return a directory outside the scanned checkout for Checkov's cwd."""
    purelib = Path(sysconfig.get_path("purelib"))
    if purelib.is_dir():
        return purelib
    # This fallback is still package-relative and, unlike the scan target, is
    # controlled by tf-eu-guard. ``-I`` below prevents cwd/PYTHONPATH shadowing.
    return Path(__file__).resolve().parent


def checkov_environment() -> dict[str, str]:
    """Return an environment without Checkov's user-configurable scan filters."""
    environment = os.environ.copy()
    for name in CHECKOV_CONFIG_ENV_VARS:
        environment.pop(name, None)
    return environment


def reject_unsupported_source_files(target: Path, iac_type: str) -> None:
    """Reject source formats that Checkov silently ignores for this framework."""
    if iac_type != "terraform":
        return
    json_sources = sorted(target.rglob("*.tf.json"))
    if json_sources:
        names = ", ".join(str(path) for path in json_sources[:5])
        if len(json_sources) > 5:
            names += f", ... and {len(json_sources) - 5} more"
        raise ValueError(
            "Terraform JSON source files (*.tf.json) are not supported by "
            f"Checkov's {iac_type} source framework: {names}. Convert the "
            "configuration to .tf HCL or scan a Terraform plan JSON with "
            "--iac-type terraform_plan."
        )


def is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is inside *root*, including the root itself."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate_scan_root_symlinks(scan_root: Path) -> None:
    """Reject links that escape a directory scan's resolved root."""
    root = scan_root.resolve(strict=True)
    pending = [root]
    visited: set[Path] = set()

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
            candidate = Path(entry.path)
            if entry.is_symlink():
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        f"Symlink '{candidate}' is broken or cannot be resolved"
                    ) from exc
                if not is_within(resolved, root):
                    raise ValueError(
                        f"Symlink '{candidate}' resolves outside scan root '{root}' "
                        f"to '{resolved}'"
                    )
                if resolved.is_dir():
                    pending.append(resolved)
            elif entry.is_dir(follow_symlinks=False):
                pending.append(candidate)


def run_checkov(target: Path, iac_type: str = "terraform") -> dict[str, Any]:
    """Run Checkov against a directory or plan file and return parsed JSON."""
    if iac_type not in SUPPORTED_IAC_TYPES:
        raise ValueError(
            f"Unsupported iac_type '{iac_type}' — expected one of "
            f"{', '.join(SUPPORTED_IAC_TYPES)}"
        )
    target = Path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

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
        validate_scan_root_symlinks(target)
        reject_unsupported_source_files(target, iac_type)
        target_flag = ["-d", str(target)]

    cmd = [
        sys.executable, "-I", "-c", CHECKOV_BOOTSTRAP,
        *target_flag,
        "--external-checks-dir", str(checks_dir),
        "--output", "json",
        "--framework", iac_type,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        cwd=trusted_checkov_workdir(),
        env=checkov_environment(),
    )

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

    return validate_scan_output(checkov_output, iac_type)
