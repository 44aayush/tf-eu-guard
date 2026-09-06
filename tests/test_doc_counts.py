"""Tests for tools/check_doc_counts.py — the doc-count drift guard.

Hand-typed mapping counts in the README drifted once (stale 38/44/30 alongside
the real 116/23/22/24); this check regenerates them from the registry files so
the drift can't recur. The pytest wrapper keeps plain ``pytest`` a sufficient
gate (CI additionally runs the script directly).
"""

import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_doc_counts  # noqa: E402


def test_computed_counts_match_current_registries():
    counts = check_doc_counts.compute_counts()
    assert counts["aws"] == 116
    assert counts["azure"] == 23
    assert counts["gcp"] == 22
    assert counts["kubernetes"] == 24
    assert counts["total"] == counts["aws"] + counts["azure"] + counts["gcp"] + counts["kubernetes"]


def test_all_documented_counts_match_the_registries():
    """Every documented mapping count agrees with the registry files."""
    assert check_doc_counts.main() == 0


def test_check_detects_a_stale_count(tmp_path, monkeypatch, capsys):
    """A doctored doc count must fail the check — the guard actually guards."""
    original_read_text = Path.read_text

    def doctored_read_text(self, *args, **kwargs):
        text = original_read_text(self, *args, **kwargs)
        if self.name == "README.md":
            # 38 is the historical stale count this tool exists to catch
            text = text.replace("AWS: 116 mappings", "AWS: 38 mappings")
        return text

    monkeypatch.setattr(Path, "read_text", doctored_read_text)
    assert check_doc_counts.main() == 1
    err = capsys.readouterr().err
    assert "DOC COUNT CHECK FAILED" in err
    assert "AWS mappings" in err
    assert "registries say (116,)" in err
