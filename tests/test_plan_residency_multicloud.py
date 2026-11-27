"""Azure and GCP resource-level residency checks run in plan mode (TEG-05)."""

import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest
from cli_helpers import run_cli

requires_checkov = pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV") or importlib.util.find_spec("checkov") is None,
    reason="live Checkov test: set TFEG_RUN_CHECKOV=1 with Checkov installed",
)

PLAN = Path(__file__).parent / "fixtures" / "plan-azure-gcp.json"


@pytest.fixture
def plan_findings(monkeypatch, tmp_path, capsys):
    shutil.copy(PLAN, tmp_path / "plan.json")
    run_cli(
        monkeypatch, tmp_path, str(tmp_path / "plan.json"), "--no-config", "--iac-type", "terraform_plan",
        "--output", "json", "--json-format", "object",
    )  # fmt: skip
    findings = json.loads(capsys.readouterr().out)["findings"]
    by_resource: dict[str, set[str]] = {}
    for finding in findings:
        by_resource.setdefault(finding["resource"], set()).add(finding["check_id"])
    return by_resource


@requires_checkov
def test_plan_mode_azure_residency(plan_findings):
    assert {"EUGUARD_POLICY_003", "EUGUARD_GDPR_004"} <= plan_findings["azurerm_storage_account.us"]
    assert not {"EUGUARD_POLICY_003", "EUGUARD_GDPR_004"} & plan_findings.get(
        "azurerm_storage_account.eu", set()
    )


@requires_checkov
def test_plan_mode_gcp_residency(plan_findings):
    assert {"EUGUARD_POLICY_004", "EUGUARD_GDPR_005"} <= plan_findings["google_storage_bucket.us"]
    assert not {"EUGUARD_POLICY_004", "EUGUARD_GDPR_005"} & plan_findings.get(
        "google_storage_bucket.eu", set()
    )


@requires_checkov
def test_plan_mode_azure_global_location(plan_findings):
    assert "EUGUARD_POLICY_003" in plan_findings["azurerm_monitor_action_group.g"]


@requires_checkov
def test_plan_mode_no_policy_005_006(plan_findings):
    emitted = set().union(*plan_findings.values())
    assert not {"EUGUARD_POLICY_005", "EUGUARD_POLICY_006"} & emitted
