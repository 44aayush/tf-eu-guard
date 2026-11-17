"""tools/check_region_drift.py against small fake botocore partition data."""

import json
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_region_drift as drift  # noqa: E402


def _write(path, partitions):
    path.write_text(json.dumps({"version": 3, "partitions": partitions}), encoding="utf-8")
    return path


def _partition(name, *regions):
    return {"partition": name, "regions": {r: {"description": r} for r in regions}}


def test_no_drift_exits_zero(tmp_path, capsys):
    data = _write(tmp_path / "endpoints.json", [_partition("aws", "us-east-1", "eu-west-1")])
    assert drift.main([str(data)]) == 0
    assert "OK" in capsys.readouterr().out


def test_drift_reports_missing_regions_and_exits_one(tmp_path, capsys):
    data = _write(
        tmp_path / "endpoints.json",
        [_partition("aws", "us-east-1", "xx-new-1"), _partition("aws-iso", "us-iso-zzz-9")],
    )
    assert drift.main([str(data)]) == 1
    err = capsys.readouterr().err
    assert "xx-new-1" in err and "us-iso-zzz-9" in err and "aws-iso" in err
    assert "us-east-1" not in err


def test_directory_argument_finds_endpoints_json(tmp_path):
    _write(tmp_path / "endpoints.json", [_partition("aws", "us-east-1")])
    assert drift.main([str(tmp_path)]) == 0


def test_unreadable_data_exits_two(tmp_path, capsys):
    assert drift.main([str(tmp_path / "missing.json")]) == 2
    (tmp_path / "bad.json").write_text("{}", encoding="utf-8")
    assert drift.main([str(tmp_path / "bad.json")]) == 2


def test_find_missing_ignores_extra_known_regions():
    regions = {"aws": {"a-1"}}
    assert drift.find_missing(regions, frozenset({"a-1", "b-2"})) == {}
    assert drift.find_missing(regions, frozenset()) == {"aws": ["a-1"]}


@pytest.mark.parametrize("region", ["ap-east-2", "ap-southeast-6"])
def test_recent_regions_are_known(region):
    from tf_eu_guard.regions import KNOWN_AWS_REGIONS

    assert region in KNOWN_AWS_REGIONS


def test_unclassified_region_is_not_drift(tmp_path):
    data = _write(tmp_path / "endpoints.json", [_partition("aws-iso-e", "eu-isoe-west-1")])
    assert drift.main([str(data)]) == 0
