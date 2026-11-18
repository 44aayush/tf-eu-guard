"""Tracked Markdown must use plain fenced code, not HTML-styled code (GitHub strips styles)."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def tracked_markdown_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git unavailable")
    return [ROOT / p for p in out.splitlines() if not Path(p).name.startswith("TASKS")]


def test_markdown_has_no_html_styled_code():
    for path in tracked_markdown_files():
        if not path.exists():  # tracked but deleted in the working tree
            continue
        text = path.read_text(encoding="utf-8")
        assert "<pre><code>" not in text, path
        assert "<span style=" not in text, path
