"""Static checks on project metadata and test-suite bootstrap."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_conftest_adds_repo_root_to_sys_path_before_importing_package():
    text = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    insert = text.index("sys.path.insert(0, str(REPO_ROOT))")
    first_import = re.search(r"^(from|import) tf_eu_guard", text, re.MULTILINE)
    assert first_import is not None
    assert insert < first_import.start()


def test_license_is_spdx_string_with_license_file():
    project = PYPROJECT["project"]
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    # PEP 639: a license expression must not be combined with a License classifier.
    assert not any(c.startswith("License ::") for c in project["classifiers"])


def test_build_backend_supports_pep_639():
    requires = PYPROJECT["build-system"]["requires"]
    pin = next(r for r in requires if r.startswith("hatchling"))
    version = tuple(int(x) for x in re.search(r"(\d+(?:\.\d+)*)", pin).group(1).split("."))
    assert version >= (1, 27)


def test_development_status_matches_zero_major_version():
    project = PYPROJECT["project"]
    assert project["version"].startswith("0.")
    assert "Development Status :: 4 - Beta" in project["classifiers"]
    assert not any("Production/Stable" in c for c in project["classifiers"])


def test_security_policy_names_current_release_line():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    minor = ".".join(PYPROJECT["project"]["version"].split(".")[:2])
    assert f"{minor}.x" in text


def test_changelog_compare_links_use_v_prefixed_tags():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    links = re.findall(r"^\[[^\]]+\]: \S*/compare/(\S+)$", text, re.MULTILINE)
    assert links
    tag = r"v\d+\.\d+\.\d+"
    for spec in links:
        base, _, head = spec.partition("...")
        assert re.fullmatch(tag, base), spec
        assert re.fullmatch(f"{tag}|HEAD", head), spec
