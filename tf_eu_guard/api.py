"""Stable Python API: ``tf_eu_guard.scan``."""

import contextlib
import io
from collections.abc import Sequence
from pathlib import Path

from tf_eu_guard.cli.app import ScanResult, prepare_scan_args, run_scan

__all__ = ["ScanResult", "scan"]


def scan(
    path: str | Path | None = None,
    *,
    iac_type: str = "terraform",
    checkov_json: str | Path | None = None,
    framework: str = "all",
    residency_policy: str = "eu-eea",
    allowed_regions: Sequence[str] | None = None,
    exclude: Sequence[str] = (),
    var_files: Sequence[str | Path] = (),
    registry_dirs: Sequence[str | Path] = (),
    waivers: str | Path | None = None,
    baseline: str | Path | None = None,
    config: str | Path | None = None,
    no_config: bool = False,
    secrets: bool = False,
    timeout: float = 600,
) -> ScanResult:
    """Scan like the CLI and return the result; never prints to stdout or exits.

    Invalid arguments raise ``ValueError``; config, waiver, baseline and scanner
    errors raise the same exceptions the CLI maps to exit codes.

    Keywords left at their default yield to a config file (``config=`` or a
    ``.tf-eu-guard.yaml`` discovered in the scan root); ``no_config=True`` makes the
    keywords authoritative and also ignores ``config=``.
    """
    argv = ["scan"]
    if path is not None:
        argv.append(str(path))
    scalars = {
        "iac-type": (iac_type, "terraform"),
        "checkov-json": (checkov_json, None),
        "framework": (framework, "all"),
        "residency-policy": (residency_policy, "eu-eea"),
        "allowed-regions": (",".join(allowed_regions) if allowed_regions else None, None),
        "waivers": (waivers, None),
        "baseline": (baseline, None),
        "config": (config, None),
        "timeout": (timeout, 600),
    }
    for flag, (value, default) in scalars.items():
        if value != default:
            argv += [f"--{flag}", str(value)]
    for flag, values in (
        ("exclude", exclude),
        ("var-file", var_files),
        ("registry-dir", registry_dirs),
    ):
        for value in values:
            argv += [f"--{flag}", str(value)]
    if secrets:
        argv.append("--secrets")
    if no_config:
        argv.append("--no-config")

    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured):
            args = prepare_scan_args(argv)
    except SystemExit as error:
        raise ValueError(captured.getvalue().strip() or "invalid arguments") from error
    return run_scan(args, with_provenance=True)
