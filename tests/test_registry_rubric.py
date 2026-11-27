"""Registry severity rubric and the T-15 / TEG-11 mapping fixes."""

import importlib.util
import os
import textwrap

import pytest

from tf_eu_guard.checkov_runner import run_checkov
from tf_eu_guard.models import Severity


def _articles(mapping):
    return {(a.framework.value, a.article) for a in mapping.articles}


@pytest.mark.parametrize(
    "cid", ["CKV_AWS_16", "CKV_AWS_96", "CKV_AWS_5", "CKV_AWS_44", "CKV_AWS_3"]
)
def test_encryption_at_rest_family_has_one_severity(registry, cid):
    """Rubric: public exposure is CRITICAL; missing encryption at rest is HIGH."""
    assert registry[cid].severity == Severity.HIGH


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
