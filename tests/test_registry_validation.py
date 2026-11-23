"""Registry loader rejections (T-34): article table, ID shape, unknown keys."""

from pathlib import Path

import pytest

from tf_eu_guard.mapping.loader import (
    RegistryValidationError,
    load_registry,
    load_registry_file,
    validate_all,
)
from tf_eu_guard.mapping.schema import CHECK_ID_RE

NIS2_E = "Security in network and information systems acquisition, development and maintenance"


def _entry(
    article: str = "Art. 21(2)(e)",
    framework: str = "NIS2",
    title: str = NIS2_E,
    extra_entry: str = "",
    extra_article: str = "",
) -> str:
    return f"""
  check_name: "x"
  articles:
    - framework: {framework}
      article: "{article}"
      title: "{title}"
{extra_article}  risk: r
  remediation: m
  severity: HIGH
{extra_entry}"""


def _load(tmp_path: Path, check_id: str, body: str):
    path = tmp_path / "registry-aws.yaml"
    path.write_text(f"{check_id}:{body}", encoding="utf-8")
    return load_registry_file(path)


def test_valid_entry_loads(tmp_path):
    assert "CKV_AWS_1" in _load(tmp_path, "CKV_AWS_1", _entry())


def test_unknown_article_is_rejected_with_file_entry_and_article(tmp_path):
    with pytest.raises(RegistryValidationError) as exc:
        _load(tmp_path, "CKV_AWS_1", _entry(article="Art. 21(2)(z)", title="Whatever"))
    msg = str(exc.value)
    assert "registry-aws.yaml" in msg and "CKV_AWS_1" in msg and "Art. 21(2)(z)" in msg


def test_article_from_other_framework_is_rejected(tmp_path):
    with pytest.raises(RegistryValidationError, match="belongs to NIS2"):
        _load(tmp_path, "CKV_AWS_1", _entry(framework="GDPR"))


@pytest.mark.parametrize("bad_id", ["ckv_aws_1", "CKV_AWS", "FOO_1", "EUGUARD_NIS2_1", "CKV_X_1"])
def test_malformed_check_id_is_rejected(tmp_path, bad_id):
    with pytest.raises(RegistryValidationError, match="check ID"):
        _load(tmp_path, bad_id, _entry())


def test_unknown_entry_key_is_rejected(tmp_path):
    with pytest.raises(RegistryValidationError, match=r"unknown key\(s\) \['sevrity'\]"):
        _load(tmp_path, "CKV_AWS_1", _entry(extra_entry="  sevrity: HIGH\n"))


def test_unknown_article_key_is_rejected(tmp_path):
    with pytest.raises(RegistryValidationError, match=r"unknown article key\(s\) \['url'\]"):
        _load(tmp_path, "CKV_AWS_1", _entry(extra_article="      url: x\n"))


@pytest.mark.parametrize(
    "good_id",
    ["CKV_AWS_21", "CKV2_AWS_6", "CKV_TF_1", "CKV_K8S_16", "CKV2_K8S_6", "EUGUARD_NIS2_003"],
)
def test_id_pattern_accepts_known_shapes(good_id):
    assert CHECK_ID_RE.fullmatch(good_id)


def test_all_shipped_registries_load():
    counts = validate_all()
    assert set(counts) == {
        f"registry-{n}.yaml" for n in ("aws", "azure", "gcp", "kubernetes", "secrets")
    }
    mapping_dir = Path(__file__).parent.parent / "tf_eu_guard" / "mapping"
    registry = load_registry(mapping_dir)
    assert len(registry) == sum(counts.values())
    assert all(CHECK_ID_RE.fullmatch(cid) for cid in registry)
