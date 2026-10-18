"""Path and framework-text helpers used by the command-line interface."""

import re
from pathlib import Path


def find_repository_root(scan_root: Path | None = None) -> Path | None:
    """Find the checkout root available to the SARIF report.

    The CLI normally runs from the checkout root, but accepting a scan path
    outside the current directory is useful for tests and CI wrappers. Look
    from both locations without invoking Git or changing scan behavior.
    """
    starts: list[Path] = []
    if scan_root is not None:
        target = scan_root.expanduser()
        if not target.is_absolute():
            target = Path.cwd() / target
        starts.append(target if target.is_dir() else target.parent)
    starts.append(Path.cwd())

    seen: set[Path] = set()
    for start in starts:
        resolved = start.resolve(strict=False)
        for candidate in (resolved, *resolved.parents):
            if candidate in seen:
                continue
            seen.add(candidate)
            if (candidate / ".git").exists():
                return candidate
    return None


def sarif_scan_root(path: Path | None, iac_type: str) -> Path | None:
    """Return the directory whose paths Checkov reports relative to."""
    if path is None:
        return None
    # Plan mode scans a file, so its containing directory is the meaningful
    # scan root for a finding such as ``/plan.json``.
    return path.parent if iac_type == "terraform_plan" else path


def scope_risk_text(text: str, selected_framework: str) -> str:
    """Remove article citations belonging to an excluded framework."""
    other_framework = "GDPR" if selected_framework == "NIS2" else "NIS2"
    pattern = rf"\b{other_framework}\s+Art\.\s+\d+(?:\([^)]*\))*"
    return re.sub(pattern, "the relevant safeguard", text)
