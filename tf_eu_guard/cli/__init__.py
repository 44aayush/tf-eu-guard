"""Public CLI entry point and compatibility exports."""

import sys
from pathlib import Path

from tf_eu_guard.cli import pipeline
from tf_eu_guard.cli.app import main as _run_main
from tf_eu_guard.cli.errors import exit_code_for

# Private name kept importable from ``tf_eu_guard.cli`` for tests.
_exit_code_for = exit_code_for


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
    return _run_main(registry_path or pipeline.default_registry_dir())


__all__ = ["main"]
