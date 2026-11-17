"""Public CLI entry point and compatibility exports."""

import sys
from pathlib import Path

from tf_eu_guard.cli.app import main as _run_main
from tf_eu_guard.cli.errors import exit_code_for
from tf_eu_guard.cli.parser import build_parser, fail_on_severity_arg
from tf_eu_guard.cli.paths import (
    find_repository_root,
    sarif_scan_root,
    scope_risk_text,
)

# Keep the existing private names importable from ``tf_eu_guard.cli``. The
# aliases make the package split transparent to callers and tests.
_build_parser = build_parser
_exit_code_for = exit_code_for
_fail_on_severity_arg = fail_on_severity_arg
_find_repository_root = find_repository_root
_sarif_scan_root = sarif_scan_root
_scope_risk_text = scope_risk_text


def _default_registry_path() -> Path:
    """Resolve the registry directory shipped inside the package."""
    return Path(__file__).parent.parent / "mapping"


def _ensure_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so reports with symbols survive redirection.

    On Windows, redirected streams use the ANSI code page, which cannot encode
    the report symbols. Streams without ``reconfigure`` (StringIO, capture
    wrappers) are left alone.
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
        if encoding in ("utf-8", "utf8"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def main(registry_path: Path | None = None) -> int:
    """Run the command-line interface.

    ``registry_path`` remains an internal/test injection seam. Normal callers
    use the registries shipped with the package.
    """
    _ensure_utf8_streams()
    return _run_main(registry_path or _default_registry_path())


__all__ = ["main"]
