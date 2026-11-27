"""Tests for tools/generate_checkov_coverage.py, the per-release Checkov coverage table.

The unit tests use small in-memory catalogues so they need no Checkov; the
drift test runs the real ``--check`` and only when Checkov is importable.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import generate_checkov_coverage as gcc  # noqa: E402

CATALOGUE = {
    "CKV_AWS_1": "one",
    "CKV_AWS_10": "ten",
    "CKV_AWS_2": "two",
    "CKV2_AZURE_3": "three",
    "CKV_K8S_4": "four",
    "CKV_GCP_5": "five",
    "CKV_TF_1": "tf",
}


def test_classify_statuses():
    rows = gcc.classify(CATALOGUE, {"CKV_AWS_1"}, {"CKV_AWS_10": "covered by CKV_AWS_9"})
    by_id = {row.check_id: row for row in rows}
    assert by_id["CKV_AWS_1"].status == "mapped"
    assert by_id["CKV_AWS_10"].status == "intentionally unmapped"
    assert by_id["CKV_AWS_10"].reason == "covered by CKV_AWS_9"
    assert by_id["CKV_AWS_2"].status == "untriaged"
    assert by_id["CKV2_AZURE_3"].provider == "Azure"
    assert by_id["CKV_K8S_4"].provider == "Kubernetes"
    assert by_id["CKV_GCP_5"].provider == "GCP"
    assert by_id["CKV_TF_1"].provider == "Terraform (cloud-agnostic)"
    assert by_id["CKV_AWS_1"].name == "one"


def test_untriaged_is_not_an_error():
    assert gcc.problems(CATALOGUE, set(), {}, {}) == []


def test_stale_registry_id_fails_check():
    mapped = {"CKV_AWS_1", "CKV_AWS_999", "EUGUARD_POLICY_001", "CKV_SECRET_6"}
    # Custom and secrets IDs are outside the Checkov catalogue prefixes.
    assert gcc.stale_ids(CATALOGUE, mapped) == ["CKV_AWS_999"]
    assert any("CKV_AWS_999" in p for p in gcc.problems(CATALOGUE, mapped, {}, {}))
    assert gcc.problems(CATALOGUE, mapped, {}, {"CKV_AWS_999": "removed upstream"}) == []


def test_triage_id_absent_from_catalogue_fails():
    # Neither list may keep an ID that Checkov no longer defines, unless it is still in a registry
    # (a known_stale entry for an ID the registry still maps stays allowed).
    found = gcc.problems(CATALOGUE, set(), {"CKV_AWS_998": "gone"}, {"CKV_AWS_997": "gone"})
    assert any("CKV_AWS_998" in p for p in found)
    assert any("CKV_AWS_997" in p for p in found)
    assert gcc.problems(CATALOGUE, {"CKV_AWS_999"}, {}, {"CKV_AWS_999": "removed upstream"}) == []


def test_load_triage_rejects_unknown_key(tmp_path):
    path = tmp_path / "triage.yaml"
    path.write_text("intentionally_unmapped: {}\nknown_stal: {}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="known_stal"):
        gcc.load_triage(path)
    path.write_text("intentionally_unmapped:\n  CKV_AWS_1: why\n", encoding="utf-8")
    assert gcc.load_triage(path) == ({"CKV_AWS_1": "why"}, {})


@pytest.mark.skipif(importlib.util.find_spec("checkov") is None, reason="needs Checkov")
def test_check_reports_stale_doc(tmp_path, capsys):
    doc = tmp_path / "checkov-coverage.md"
    assert gcc.main(["--doc", str(doc)]) == 0
    assert gcc.main(["--check", "--doc", str(doc)]) == 0
    lines = doc.read_text(encoding="utf-8").splitlines()
    lines[-1] += " changed"
    doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
    capsys.readouterr()
    assert gcc.main(["--check", "--doc", str(doc)]) == 1
    assert doc.name in capsys.readouterr().err


def test_triage_and_mapping_conflict_fails():
    found = gcc.problems(CATALOGUE, {"CKV_AWS_1"}, {"CKV_AWS_1": "reason"}, {})
    assert len(found) == 1
    assert "CKV_AWS_1" in found[0]


def test_render_summary_counts():
    rows = gcc.classify(CATALOGUE, {"CKV_AWS_1"}, {"CKV_AWS_10": "why"})
    doc = gcc.render(rows, "9.9.9")
    assert "Checkov 9.9.9" in doc
    assert "| AWS | 3 | 1 | 1 | 1 |" in doc
    assert "| Azure | 1 | 0 | 0 | 1 |" in doc
    # Sorted by ID with the number compared numerically.
    assert doc.index("| CKV_AWS_1 |") < doc.index("| CKV_AWS_2 |") < doc.index("| CKV_AWS_10 |")


@pytest.mark.skipif(importlib.util.find_spec("checkov") is None, reason="needs Checkov")
def test_doc_is_current():
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "generate_checkov_coverage.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_doc_flag_without_value_exits_with_message(capsys):
    with pytest.raises(SystemExit) as exc:
        gcc.main(["--check", "--doc"])
    assert exc.value.code == 2
    assert "--doc" in capsys.readouterr().err


def test_doc_flag_followed_by_flag_is_error(capsys):
    with pytest.raises(SystemExit) as exc:
        gcc.main(["--doc", "--check"])
    assert exc.value.code == 2
    assert "--doc" in capsys.readouterr().err
