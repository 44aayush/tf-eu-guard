"""Residency policy (T-06) and resource-level region checks (T-07)."""

import json

import pytest
from checkov.common.models.enums import CheckResult

from tests.cli_helpers import run_cli
from tf_eu_guard.checkov import process
from tf_eu_guard.checks.gdpr.data_residency import (
    EURegionEnforcement,
    ResourceRegionPolicy,
    ResourceThirdCountryTransferReview,
)
from tf_eu_guard.checks.regions_conf import collect_regions
from tf_eu_guard.regions import EU_EEA_REGIONS, EUSC_REGIONS
from tf_eu_guard.residency import (
    ALLOWED_REGIONS_ENV_VAR,
    POLICY_ENV_VAR,
    allowed_regions_from_env,
    aws_region_unset_warning,
    parse_allowed_regions,
    residency_env,
)

RESOURCES = "tests/fixtures/residency-resources"
CLEAN = "tests/fixtures/residency-clean"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.delenv(ALLOWED_REGIONS_ENV_VAR, raising=False)


def _provider(region):
    return EURegionEnforcement().scan_provider_conf({"region": [region]})


def test_default_policy_is_eu_eea():
    assert _provider("eu-central-1") == CheckResult.PASSED
    assert _provider("eusc-de-east-1") == CheckResult.PASSED
    assert _provider("us-east-1") == CheckResult.FAILED
    assert _provider("eu-west-2") == CheckResult.FAILED
    assert _provider("var.region") == CheckResult.FAILED
    assert EURegionEnforcement().scan_provider_conf({}) == CheckResult.UNKNOWN
    assert allowed_regions_from_env({}) == EU_EEA_REGIONS


def test_eusc_policy(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "eusc")
    assert _provider("eu-central-1") == CheckResult.FAILED
    assert _provider("eusc-de-east-1") == CheckResult.PASSED
    assert allowed_regions_from_env({POLICY_ENV_VAR: "eusc"}) == EUSC_REGIONS


def test_custom_policy(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    monkeypatch.setenv(ALLOWED_REGIONS_ENV_VAR, "EU-West-1, eu-north-1")
    assert _provider("eu-west-1") == CheckResult.PASSED
    assert _provider("eu-central-1") == CheckResult.FAILED


@pytest.mark.parametrize(
    "env",
    [
        {POLICY_ENV_VAR: "bogus"},
        {POLICY_ENV_VAR: "custom"},
        {POLICY_ENV_VAR: "custom", ALLOWED_REGIONS_ENV_VAR: "not a region!"},
    ],
)
def test_invalid_policy_env_fails_closed_to_eusc(env):
    assert allowed_regions_from_env(env) == EUSC_REGIONS


def test_parse_allowed_regions_normalises_and_validates():
    assert parse_allowed_regions(" EU-West-1,eu-north-1 ,eu-west-1") == ("eu-north-1", "eu-west-1")
    with pytest.raises(ValueError):
        parse_allowed_regions(" , ")
    with pytest.raises(ValueError):
        parse_allowed_regions("eu west")


# --- resource-level collection and checks ------------------------------------


def _res(rtype, conf):
    return collect_regions(rtype, conf)


def test_collect_regions_shapes():
    assert [r.region for r in _res("aws_s3_bucket", {"region": ["us-east-1"]})] == ["us-east-1"]
    dyn = {"replica": [{"region_name": ["us-east-1"]}, {"region_name": ["eu-west-1"]}]}
    refs = _res("aws_dynamodb_table", dyn)
    assert [(r.region, r.key) for r in refs] == [
        ("us-east-1", "replica/[0]/region_name"),
        ("eu-west-1", "replica/[1]/region_name"),
    ]
    ecr = {"replication_configuration": [{"rule": [{"destination": [{"region": ["us-west-2"]}]}]}]}
    assert [r.region for r in _res("aws_ecr_replication_configuration", ecr)] == ["us-west-2"]
    backup = {
        "rule": [
            {
                "copy_action": [
                    {"destination_vault_arn": ["arn:aws:backup:us-east-2:123:backup-vault:v"]}
                ]
            }
        ]
    }
    assert [r.region for r in _res("aws_backup_plan", backup)] == ["us-east-2"]
    unresolved = {
        "rule": [{"copy_action": [{"destination_vault_arn": ["aws_backup_vault.x.arn"]}]}]
    }
    assert _res("aws_backup_plan", unresolved) == []
    # S3 replication destinations are not resolvable statically.
    s3 = {"rule": [{"destination": [{"bucket": ["arn:aws:s3:::other"]}]}]}
    assert _res("aws_s3_bucket_replication_configuration", s3) == []
    assert _res("aws_s3_bucket", {"bucket": ["x"]}) == []


def _policy2(rtype, conf):
    check = ResourceRegionPolicy()
    check.entity_type = rtype
    return check.scan_resource_conf(conf), check.evaluated_keys


def _gdpr3(rtype, conf):
    check = ResourceThirdCountryTransferReview()
    check.entity_type = rtype
    return check.scan_resource_conf(conf)


def test_policy_002_semantics(monkeypatch):
    assert _policy2("aws_s3_bucket", {"bucket": ["x"]})[0] == CheckResult.UNKNOWN
    assert _policy2("aws_s3_bucket", {"region": ["eu-central-1"]})[0] == CheckResult.PASSED
    result, keys = _policy2("aws_s3_bucket", {"region": ["us-east-1"]})
    assert (result, keys) == (CheckResult.FAILED, ["region"])
    assert _policy2("aws_s3_bucket", {"region": ["var.region"]})[0] == CheckResult.FAILED
    mixed = {"replica": [{"region_name": ["eu-west-1"]}, {"region_name": ["us-east-1"]}]}
    result, keys = _policy2("aws_dynamodb_table", mixed)
    assert result == CheckResult.FAILED and keys == ["replica/[1]/region_name"]
    monkeypatch.setenv(POLICY_ENV_VAR, "eusc")
    assert _policy2("aws_s3_bucket", {"region": ["eu-central-1"]})[0] == CheckResult.FAILED


def test_gdpr_003_semantics():
    assert _gdpr3("aws_s3_bucket", {}) == CheckResult.UNKNOWN
    assert _gdpr3("aws_s3_bucket", {"region": ["eu-central-1"]}) == CheckResult.PASSED
    assert _gdpr3("aws_s3_bucket", {"region": ["us-east-1"]}) == CheckResult.FAILED
    assert _gdpr3("aws_s3_bucket", {"region": ["eu-west-2"]}) == CheckResult.FAILED
    assert _gdpr3("aws_s3_bucket", {"region": ["var.region"]}) == CheckResult.UNKNOWN
    assert _gdpr3("aws_s3_bucket", {"region": ["eu-garbage-9"]}) == CheckResult.UNKNOWN


def test_check_identities():
    assert ResourceRegionPolicy().id == "EUGUARD_POLICY_002"
    assert ResourceThirdCountryTransferReview().id == "EUGUARD_GDPR_003"
    assert "configured residency policy" in EURegionEnforcement().name


# --- environment propagation -------------------------------------------------


def test_checkov_environment_drops_ambient_and_sets_explicit(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    monkeypatch.setenv(ALLOWED_REGIONS_ENV_VAR, "us-east-1")
    env = process.checkov_environment()
    assert POLICY_ENV_VAR not in env and ALLOWED_REGIONS_ENV_VAR not in env
    env = process.checkov_environment(residency_env("custom", ("eu-west-1",)))
    assert env[POLICY_ENV_VAR] == "custom"
    assert env[ALLOWED_REGIONS_ENV_VAR] == "eu-west-1"


def _capture_env(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs["env"]
        out = {"check_type": "terraform", "results": {"failed_checks": []}, "summary": {}}
        return type("R", (), {"returncode": 0, "stdout": json.dumps(out), "stderr": ""})()

    monkeypatch.setattr("tf_eu_guard.checkov_runner.subprocess.run", fake_run)
    return captured


def test_cli_propagates_policy_to_subprocess_env(monkeypatch, tmp_path, repo_root, capsys):
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "main.tf").write_text('resource "aws_x" "y" {}\n')
    monkeypatch.setenv(POLICY_ENV_VAR, "eusc")  # ambient value must not leak
    captured = _capture_env(monkeypatch)
    args = [str(tmp_path / "scan"), "--output", "json"]
    run_cli(monkeypatch, tmp_path, *args)
    assert POLICY_ENV_VAR in captured["env"] and captured["env"][POLICY_ENV_VAR] == "eu-eea"
    run_cli(monkeypatch, tmp_path, *args, "--residency-policy", "eusc")
    assert captured["env"][POLICY_ENV_VAR] == "eusc"
    assert ALLOWED_REGIONS_ENV_VAR not in captured["env"]
    run_cli(
        monkeypatch,
        tmp_path,
        *args,
        "--residency-policy",
        "custom",
        "--allowed-regions",
        " EU-West-1,eu-north-1",
    )
    assert captured["env"][POLICY_ENV_VAR] == "custom"
    assert captured["env"][ALLOWED_REGIONS_ENV_VAR] == "eu-north-1,eu-west-1"


# --- CLI parsing --------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        ["--residency-policy", "custom"],
        ["--allowed-regions", "eu-west-1"],
        ["--residency-policy", "eusc", "--allowed-regions", "eu-west-1"],
        ["--residency-policy", "custom", "--allowed-regions", "bad region"],
        ["--residency-policy", "custom", "--allowed-regions", ","],
        ["--residency-policy", "bogus"],
    ],
)
def test_cli_rejects_bad_policy_usage(monkeypatch, tmp_path, extra):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, tmp_path, str(tmp_path), *extra)
    assert exc.value.code == 2


def test_checkov_json_warns_policy_ignored(monkeypatch, tmp_path, repo_root, capsys):
    fixture = str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json")
    run_cli(monkeypatch, tmp_path, "--checkov-json", fixture, "--output", "json")
    assert "ignored" not in capsys.readouterr().err
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        fixture,
        "--residency-policy",
        "eusc",
        "--output",
        "json",
    )
    assert "--residency-policy/--allowed-regions are ignored" in capsys.readouterr().err


def test_deprecated_gdpr_001_alias_maps_from_checkov_json(monkeypatch, tmp_path, repo_root, capsys):
    fixture = repo_root / "tests/fixtures/checkov-gdpr001-alias.json"
    assert run_cli(monkeypatch, tmp_path, "--checkov-json", str(fixture), "--output", "json") == 0
    findings = json.loads(capsys.readouterr().out)
    assert [f["check_id"] for f in findings] == ["EUGUARD_GDPR_001"]
    assert findings[0]["articles"] == [{"framework": "POLICY", "article": "Policy RESIDENCY-001"}]


# --- real Checkov ---------------------------------------------------------------


def test_resource_regions_live(monkeypatch, tmp_path, repo_root, capsys):
    args = (tmp_path, str(repo_root / RESOURCES), "--output", "json")
    run_cli(monkeypatch, *args, "--residency-policy", "eusc")
    findings = json.loads(capsys.readouterr().out)
    by_resource: dict[str, set[str]] = {}
    for f in findings:
        by_resource.setdefault(f["resource"], set()).add(f["check_id"])
    for resource in (
        "aws_s3_bucket.elsewhere",
        "aws_dynamodb_table.replicated",
        "aws_secretsmanager_secret.replicated",
    ):
        assert {"EUGUARD_POLICY_002", "EUGUARD_GDPR_003"} <= by_resource[resource], resource
    assert "aws.default" not in by_resource  # eusc provider passes


def test_default_policy_provider_and_clean_fixture_live(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(monkeypatch, tmp_path, str(repo_root / CLEAN), "--output", "json")
    findings = json.loads(capsys.readouterr().out)
    assert not [f for f in findings if f["check_id"].startswith("EUGUARD_P")]
    assert not [f for f in findings if f["check_id"] == "EUGUARD_GDPR_003"]
    # eu-central-1 provider fails only under the eusc policy.
    run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / CLEAN),
        "--output",
        "json",
        "--residency-policy",
        "eusc",
    )
    strict = {f["check_id"] for f in json.loads(capsys.readouterr().out)}
    assert "EUGUARD_POLICY_001" in strict and "EUGUARD_POLICY_002" in strict


@pytest.mark.parametrize("region", ["ap-east-2", "ap-southeast-6", "us-isob-west-1"])
def test_new_aws_regions_fail_gdpr_002_and_003(region):
    from tf_eu_guard.checks.gdpr.data_residency import ThirdCountryTransferReview
    from tf_eu_guard.regions import KNOWN_AWS_REGIONS

    assert region in KNOWN_AWS_REGIONS
    assert region not in EU_EEA_REGIONS
    provider = ThirdCountryTransferReview().scan_provider_conf({"region": [region]})
    assert provider == CheckResult.FAILED
    assert _gdpr3("aws_s3_bucket", {"region": [region]}) == CheckResult.FAILED


def test_eu_isoe_is_unclassified_not_third_country():
    from tf_eu_guard.checks.gdpr.data_residency import ThirdCountryTransferReview
    from tf_eu_guard.regions import KNOWN_AWS_REGIONS, UNCLASSIFIED_AWS_REGIONS

    region = "eu-isoe-west-1"
    assert region in UNCLASSIFIED_AWS_REGIONS and region not in KNOWN_AWS_REGIONS
    assert ThirdCountryTransferReview().scan_provider_conf({"region": [region]}) == (
        CheckResult.UNKNOWN
    )
    assert _gdpr3("aws_s3_bucket", {"region": [region]}) == CheckResult.UNKNOWN
    assert _provider(region) == CheckResult.FAILED
    assert _policy2("aws_s3_bucket", {"region": [region]})[0] == CheckResult.FAILED


def _aws_output(*extra_checks):
    return {
        "results": {
            "passed_checks": [{"check_id": "EUGUARD_GDPR_002", "resource": "aws_s3_bucket.b"}],
            "failed_checks": [{"check_id": "CKV_AWS_18", "resource": "aws_s3_bucket.b"}],
            "skipped_checks": list(extra_checks),
        }
    }


def test_aws_region_unset_warning_fires_without_provider_result():
    warning = aws_region_unset_warning(_aws_output())
    assert warning is not None
    assert 'no provider "aws" block sets a region' in warning
    assert "--iac-type terraform_plan" in warning


@pytest.mark.parametrize("bucket", ["passed_checks", "failed_checks"])
def test_aws_region_unset_warning_silent_when_policy_001_ran(bucket):
    output = _aws_output()
    output["results"][bucket].append({"check_id": "EUGUARD_POLICY_001", "resource": "aws.default"})
    assert aws_region_unset_warning(output) is None


def test_aws_region_unset_warning_silent_when_no_euguard_check_ran():
    output = _aws_output()
    output["results"]["passed_checks"] = []
    assert aws_region_unset_warning(output) is None


def test_aws_region_unset_warning_silent_when_policy_001_is_skipped():
    output = _aws_output({"check_id": "EUGUARD_POLICY_001", "resource": "aws.default"})
    assert aws_region_unset_warning(output) is None


def test_aws_region_unset_warning_silent_without_aws_resources():
    output = {
        "results": {
            "failed_checks": [{"check_id": "CKV_GCP_1", "resource": "google_storage_bucket.b"}]
        }
    }
    assert aws_region_unset_warning(output) is None
    assert aws_region_unset_warning({"results": {}}) is None
