"""Registry severity rubric and the T-15 / TEG-11 mapping fixes."""

import pytest

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
