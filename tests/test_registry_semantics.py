"""Regression probes for the Azure/GCP checks reconciled with Checkov 3.3.29."""

from pathlib import Path

import checkov.terraform.checks.resource  # noqa: F401
import pytest
import yaml
from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.registry import resource_registry

from tf_eu_guard.models import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "registry-semantics.yaml"
TARGET_IDS = tuple(yaml.safe_load(FIXTURE.read_text(encoding="utf-8")))
REGISTRY_DIR = FIXTURE.parents[2] / "tf_eu_guard" / "mapping"


def _checkov_checks_by_id():
    """Load the installed Terraform Checkov registry, including Azure/GCP checks."""
    checks = {}
    for group in resource_registry.checks.values():
        for check in group:
            if check.id in TARGET_IDS:
                checks.setdefault(check.id, []).append(check)
    return checks


@pytest.fixture(scope="module")
def semantic_cases():
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def checkov_checks():
    return _checkov_checks_by_id()


@pytest.mark.parametrize("check_id", TARGET_IDS)
def test_registry_entry_matches_checkov_semantics(registry, semantic_cases, checkov_checks, check_id):
    case = semantic_cases[check_id]
    mapping = registry[check_id]
    checks = checkov_checks[check_id]

    assert checks, f"{check_id} is not present in installed Checkov"
    assert mapping.check_name == case["check_name"]
    assert {check.name for check in checks} == {mapping.check_name}
    assert {resource for check in checks for resource in check.supported_resources} >= {
        case["supported_resource"]
    }
    assert mapping.severity is Severity[case["severity"]]
    assert {
        (article.framework.value, article.article) for article in mapping.articles
    } == {tuple(article) for article in case["articles"]}
    assert all(text in mapping.remediation for text in case["remediation_contains"])

    for check in checks:
        assert check.scan_resource_conf(case["fail_conf"]) is CheckResult.FAILED
        assert check.scan_resource_conf(case["pass_conf"]) is CheckResult.PASSED


def test_target_ids_are_exactly_the_fixture_scope():
    """Every Azure/GCP registry ID must have a semantic fixture."""
    registry_ids = set()
    for path in (REGISTRY_DIR / "registry-azure.yaml", REGISTRY_DIR / "registry-gcp.yaml"):
        registry_ids.update(yaml.safe_load(path.read_text(encoding="utf-8")))
    assert set(TARGET_IDS) == registry_ids
