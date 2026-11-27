"""tools/check_cloud_region_tables.py: Azure/GCP tables against reviewed snapshots."""

import json
import re
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_cloud_region_tables as check  # noqa: E402

from tf_eu_guard import regions  # noqa: E402


def test_region_tables_match_snapshot(capsys):
    assert check.main([]) == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("table", "code"),
    [
        ("AZURE_EU_EEA_LOCATIONS", "westeurope"),
        ("AZURE_KNOWN_LOCATIONS", "eastus"),
        ("GCP_EU_EEA_LOCATIONS", "europe-west4"),
        ("GCP_KNOWN_LOCATIONS", "us-central1"),
    ],
)
def test_drift_check_fails_on_missing_region(monkeypatch, capsys, table, code):
    monkeypatch.setattr(regions, table, getattr(regions, table) - {code})
    assert check.main([]) == 1
    assert code in capsys.readouterr().err


def test_drift_check_fails_on_unsnapshotted_region(monkeypatch, capsys):
    monkeypatch.setattr(regions, "GCP_KNOWN_LOCATIONS", regions.GCP_KNOWN_LOCATIONS | {"mars-1"})
    assert check.main([]) == 1
    assert "mars-1" in capsys.readouterr().err


def test_drift_check_fails_on_eu_code_in_third_country_snapshot(tmp_path, capsys):
    for name in ("azure.json", "gcp.json"):
        document = json.loads((check.SNAPSHOT_DIR / name).read_text(encoding="utf-8"))
        if name == "azure.json":
            document["third_country"].append("westeurope")
        (tmp_path / name).write_text(json.dumps(document), encoding="utf-8")
    assert check.main([str(tmp_path)]) == 1
    assert "westeurope is EU/EEA but listed as a third country" in capsys.readouterr().err


def _snapshot(name):
    return json.loads((check.SNAPSHOT_DIR / name).read_text(encoding="utf-8"))


def test_load_snapshot_rejects_non_list(tmp_path):
    document = _snapshot("azure.json")
    document["eu_eea"] = "westeurope"
    path = tmp_path / "azure.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        check.load_snapshot(path)


def test_load_snapshot_rejects_non_string_items(tmp_path):
    document = _snapshot("azure.json")
    document["eu_eea"] = [1, 2]
    path = tmp_path / "azure.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        check.load_snapshot(path)


def test_unclassified_code_in_a_table_is_drift():
    document = _snapshot("azure.json")
    document["unclassified"] = sorted([*document["unclassified"], "westeurope"])
    problems = check.find_drift("azure", document)
    assert problems == ["azure: westeurope is unclassified in the snapshot but classified"]


def test_drift_check_exits_two_without_snapshot(tmp_path, capsys):
    assert check.main([str(tmp_path)]) == 2
    assert "could not run" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["azure.json", "gcp.json"])
def test_snapshot_has_source_and_date(name):
    document = json.loads((check.SNAPSHOT_DIR / name).read_text(encoding="utf-8"))
    assert document["source"].startswith("https://")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", document["verified"])
    for key in ("eu_eea", "third_country", "unclassified"):
        assert isinstance(document[key], list)
        assert document[key] == sorted(document[key])


def test_list_keys_are_explicit():
    assert check.LIST_KEYS == ("eu_eea", "third_country", "unclassified")
