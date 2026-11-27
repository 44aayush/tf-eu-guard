"""Registry severity rubric and the T-15 / TEG-11 mapping fixes."""

import importlib.util
import os
import textwrap
from pathlib import Path

import pytest

from tf_eu_guard.checkov_runner import run_checkov
from tf_eu_guard.models import Severity


def _articles(mapping):
    return {(a.framework.value, a.article) for a in mapping.articles}


PUBLIC_EXPOSURE_IDS = (
    "CKV_AWS_17",
    "CKV_AWS_20",
    "CKV_AWS_70",
    "CKV_AWS_87",
    "CKV_AWS_24",
    "CKV_AWS_25",
    "CKV_AWS_38",
    "CKV_AZURE_11",
    "CKV_GCP_11",
    "CKV_GCP_28",
    "CKV_GCP_88",
)
GUARDRAIL_IDS = (
    "CKV2_AWS_6",
    "CKV_AWS_53",
    "CKV_AWS_54",
    "CKV_AWS_55",
    "CKV_AWS_56",
    "CKV_AZURE_59",
    "CKV_AZURE_139",
    "CKV_AZURE_160",
    "CKV_AZURE_48",
    "CKV_AZURE_53",
    "CKV_GCP_18",
)
ENCRYPTION_AT_REST_IDS = (
    "CKV_AWS_16",
    "CKV_AWS_3",
    "CKV_AWS_96",
    "CKV_AWS_5",
    "CKV_AWS_44",
)
CMK_IDS = (
    "CKV_AWS_119",
    "CKV_AWS_147",
    "CKV_AWS_149",
    "CKV_AWS_186",
    "CKV_AWS_189",
    "CKV_AWS_191",
    "CKV_AWS_224",
    "CKV_AWS_247",
    "CKV_AWS_280",
    "CKV_AWS_327",
    "CKV_AWS_347",
    "CKV_AWS_35",
)
RUBRIC_DOC = Path(__file__).resolve().parents[1] / "docs" / "severity-rubric.md"


@pytest.mark.parametrize("cid", PUBLIC_EXPOSURE_IDS)
def test_public_exposure_family_is_critical(registry, cid):
    """A world-open data store or admin port (SSH/RDP) is CRITICAL."""
    assert registry[cid].severity == Severity.CRITICAL


@pytest.mark.parametrize("cid", GUARDRAIL_IDS)
def test_guardrail_family_is_high(registry, cid):
    """Public-network guardrails (defence in depth against exposure) are HIGH."""
    assert registry[cid].severity == Severity.HIGH


@pytest.mark.parametrize("cid", ENCRYPTION_AT_REST_IDS)
def test_encryption_at_rest_family_is_high(registry, cid):
    """The encryption-at-rest checks for data stores all have severity HIGH."""
    assert registry[cid].severity == Severity.HIGH


@pytest.mark.parametrize("cid", CMK_IDS)
def test_cmk_family_is_medium(registry, cid):
    """A customer-managed key over a provider-managed one is key-control depth: MEDIUM."""
    assert registry[cid].severity == Severity.MEDIUM


def test_families_do_not_overlap():
    families = [PUBLIC_EXPOSURE_IDS, GUARDRAIL_IDS, ENCRYPTION_AT_REST_IDS, CMK_IDS]
    all_ids = [cid for family in families for cid in family]
    assert len(all_ids) == len(set(all_ids))


def _doc_sections():
    """Map each `### ` heading of the rubric doc to the text under it."""
    sections: dict[str, str] = {}
    heading = None
    for line in RUBRIC_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            heading = line[4:]
            sections[heading] = ""
        elif line.startswith("#"):
            heading = None
        elif heading is not None:
            sections[heading] += line + "\n"
    return sections


@pytest.mark.parametrize(
    ("heading", "ids"),
    [
        ("Public exposure of a data store or an admin port: CRITICAL", PUBLIC_EXPOSURE_IDS),
        ("Public-network guardrails: HIGH", GUARDRAIL_IDS),
        ("Data-store encryption at rest: HIGH", ENCRYPTION_AT_REST_IDS),
        ("Customer-managed key instead of a provider-managed key: MEDIUM", CMK_IDS),
    ],
)
def test_rubric_doc_lists_every_family_id(heading, ids):
    """Each ID appears under its own family heading in docs/severity-rubric.md."""
    section = _doc_sections()[heading]
    missing = [cid for cid in ids if f"`{cid}`" not in section]
    assert not missing, f"'{heading}' does not list {missing}"


@pytest.mark.parametrize("cid", CMK_IDS)
def test_cmk_risk_texts_are_hedged(registry, cid):
    """A CMK is key-control depth, not a stated requirement: the risk text must not say so."""
    risk = " ".join(registry[cid].risk_explanation.split())
    assert "requires" not in risk
    assert "32(1)(a) expects" not in risk


def test_ckv_aws_288_cites_no_breach_articles(registry):
    cited = _articles(registry["CKV_AWS_288"])
    assert ("GDPR", "Art. 4(12)") not in cited
    assert ("GDPR", "Art. 33") not in cited
    assert ("GDPR", "Art. 32(1)(b)") in cited
    assert ("NIS2", "Art. 21(2)(i)") in cited


def test_new_mappings_present(registry):
    logging_check = registry["CKV2_AWS_27"]
    assert logging_check.severity == registry["CKV2_AWS_30"].severity
    assert _articles(logging_check) == _articles(registry["CKV2_AWS_30"])
    assert "aws_rds_cluster_parameter_group" in logging_check.remediation

    ssm = registry["CKV2_AWS_34"]
    assert ssm.severity == Severity.MEDIUM
    assert _articles(ssm) == {("NIS2", "Art. 21(2)(h)"), ("GDPR", "Art. 32(1)(a)")}
    assert "SecureString" in ssm.remediation
    assert "key_id" in ssm.remediation


@pytest.mark.parametrize("cid", ["CKV2_AWS_27", "CKV2_AWS_30"])
def test_query_logging_remediations_name_checkov_parameters(registry, cid):
    remediation = registry[cid].remediation
    assert "log_statement" in remediation
    assert "log_min_duration_statement" in remediation


@pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or importlib.util.find_spec("checkov") is None,
    reason="live Checkov test: set TFEG_RUN_CHECKOV=1 with Checkov installed in this Python environment",
)
@pytest.mark.parametrize("cid", ["CKV2_AWS_27", "CKV2_AWS_30"])
def test_query_logging_remediations_clear_checkov(registry, tmp_path, cid):
    """The remediation text, written to a .tf file, must pass the check it is attached to."""
    lines = registry[cid].remediation.splitlines()[1:]  # first line is prose
    (tmp_path / "main.tf").write_text(textwrap.dedent("\n".join(lines)) + "\n", encoding="utf-8")
    data = run_checkov(tmp_path)
    passed = {c["check_id"] for c in data["results"]["passed_checks"]}
    failed = {c["check_id"] for c in data["results"]["failed_checks"]}
    assert cid in passed, f"{cid} did not pass (failed: {sorted(failed)})"
