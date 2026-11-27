"""Documentation claims that were corrected in review must not reappear.

Each assertion pins one wording that was shown to be false: the Scanned-code
execution claim, the `--var-file` support claim, a registry typo, and the
residency scope of the custom checks.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_docs_do_not_repeat_corrected_claims():
    security = _read("SECURITY.md")
    assert "never executed" not in security

    limitations = _read("docs/limitations.md")
    assert "no `--var-file` support" not in limitations

    for registry in sorted((ROOT / "tf_eu_guard" / "mapping").glob("registry-*.yaml")):
        assert "weakensing" not in registry.read_text(encoding="utf-8"), registry.name

    assert "AWS only" in _read("README.md")
