"""T-04 / T-05: reference-vs-literal and name/value heuristics for NIS2_001/002."""

import pytest

pytest.importorskip("checkov")

from checkov.common.models.enums import CheckResult  # noqa: E402

from tf_eu_guard.checkov_runner import extract_failed_checks, run_checkov  # noqa: E402
from tf_eu_guard.checks.k8s.secrets_in_code import (  # noqa: E402
    K8sContainerEnvHardcodedSecrets,
    K8sSecretManifestHardcodedSecrets,
)
from tf_eu_guard.checks.nis2.secret_names import (  # noqa: E402
    has_embedded_credentials,
    is_literal_secret_value,
    is_reference_value,
    is_sensitive_env_name,
)
from tf_eu_guard.checks.nis2.secrets_in_code import _scan_codebuild_env  # noqa: E402

REFERENCES = [
    'jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]',
    "random_password.db[0].result",
    'var.passwords["db"]',
    "try(var.pw, null)",
    "try(var.pw,None)",  # Checkov's normalised form
    "sensitive(var.pw)",
    "${var.x}",
    "${var.a}${var.b}",
    '${ jsondecode(local.s)["k"] }',
    "var.x",
    "aws_secretsmanager_secret_version.db.secret_string",
    "module.db.password",
]
LITERALS = [
    "db_admin.Password1",
    'hunter2${""}',
    "prod-${var.env}-Hunter2",
    "${var.a}-${var.b}",
    "literal.with.dots",
    "ChangeMe123!",
]


@pytest.mark.parametrize("value", REFERENCES)
def test_reference_shapes(value):
    assert is_reference_value(value) is True
    assert is_literal_secret_value(value) is False


@pytest.mark.parametrize("value", LITERALS)
def test_literal_shapes(value):
    assert is_reference_value(value) is False
    assert is_literal_secret_value(value) is True


def test_secret_shapes_refs_live_checkov(repo_root):
    """Real Checkov output: references pass, literals fail."""
    result = run_checkov(repo_root / "tests" / "fixtures" / "secret-shapes-refs")
    flagged = {
        f["resource"] for f in extract_failed_checks(result) if f["check_id"] == "EUGUARD_NIS2_001"
    }
    assert flagged == {
        "aws_db_instance.lit_dotted",
        "aws_db_instance.lit_empty_interp",
        "aws_db_instance.lit_mixed",
    }


@pytest.mark.parametrize(
    "name",
    [
        "DB_PASS",
        "SMTP_PASS",
        "PASSPHRASE",
        "SENTRY_DSN",
        "CONNECTION_STRING",
        "DB_CONN_STR",
        "GITHUB_PAT",
        "SLACK_WEBHOOK",
        "AWS_ACCESS_KEY_ID",
        "DB_PASSWORD",
    ],
)
def test_sensitive_names(name):
    assert is_sensitive_env_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "PUBLIC_KEY",
        "SSH_PUBLIC_KEY",
        "CACHE_KEY_PREFIX",
        "TOKEN_TTL",
        "TOKEN_LENGTH",
        "PARTITION_KEY",
        "SORT_KEY",
        "PATH",
        "BYPASS_CACHE",
        "LOG_LEVEL",
    ],
)
def test_non_secret_names(name):
    assert is_sensitive_env_name(name) is False


@pytest.mark.parametrize(
    "value",
    [
        "postgres://app:Sup3rS3cret@db:5432/app",
        "https://user:token@host/x",
        "https://hooks.slack.com/services/T000/B000/XXXX",
        "amqp://u:p@mq",
    ],
)
def test_embedded_credentials(value):
    assert has_embedded_credentials(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path",
        "postgres://db:5432/app",
        "postgres://app@db/app",
        "postgres://app:$(PW)@db/app",
        "",
        "plain",
    ],
)
def test_no_embedded_credentials(value):
    assert has_embedded_credentials(value) is False


def _env_check(env):
    check = K8sContainerEnvHardcodedSecrets()
    check.entity_type = "Pod"
    return check.scan_spec_conf({"spec": {"containers": [{"name": "a", "env": env}]}})


def test_k8s_env_value_inspection():
    assert _env_check([{"name": "DB_PASS", "value": "Sup3rS3cret!"}]) == CheckResult.FAILED
    assert (
        _env_check([{"name": "DATABASE_URL", "value": "postgres://app:Sup3rS3cret@db:5432/app"}])
        == CheckResult.FAILED
    )
    assert (
        _env_check([{"name": "NOTIFY", "value": "https://hooks.slack.com/services/T0/B0/X"}])
        == CheckResult.FAILED
    )
    assert (
        _env_check([{"name": "API_BASE_URL", "value": "https://u:tok@host"}]) == CheckResult.FAILED
    )


def test_k8s_env_benign_and_references_pass():
    env = [
        {"name": "PARTITION_KEY", "value": "tenant"},
        {"name": "TOKEN_TTL", "value": "3600"},
        {"name": "PUBLIC_KEY", "value": "ssh-ed25519 AAAA"},
        {"name": "DB_PASS", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
        {"name": "DB_PASS", "value": "$(OTHER)"},
        {"name": "DB_PASS", "value": ""},
        {"name": "ENDPOINT_URL", "value": "https://example.com"},
    ]
    assert _env_check(env) == CheckResult.PASSED


def _secret_check(conf):
    check = K8sSecretManifestHardcodedSecrets()
    check.entity_type = "Secret"
    return check.scan_spec_conf(conf)


def test_k8s_secret_sops_skipped():
    assert (
        _secret_check({"stringData": {"p": "plain"}, "sops": {"version": "3.8"}})
        == CheckResult.PASSED
    )
    assert _secret_check({"data": {"p": "ENC[AES256_GCM,data:x]"}}) == CheckResult.PASSED
    assert _secret_check({"data": {"p": "ENC[x]", "q": "plain"}}) == CheckResult.FAILED
    assert _secret_check({"stringData": {"p": "plain"}}) == CheckResult.FAILED


def test_k8s_live_checkov(repo_root):
    result = run_checkov(repo_root / "tests" / "fixtures" / "secret-shapes-k8s", "kubernetes")
    flagged = {
        f["resource"] for f in extract_failed_checks(result) if f["check_id"] == "EUGUARD_NIS2_003"
    }
    assert flagged == {"Deployment.default.leaky"}


@pytest.mark.parametrize(
    "name,value,expected",
    [
        ("DB_PASS", "Sup3rS3cret!", True),
        ("SENTRY_DSN", "https://abc@o1.ingest.sentry.io/1", True),
        ("DATABASE_URL", "postgres://app:Sup3rS3cret@db:5432/app", True),
        ("NOTIFY_URL", "https://hooks.slack.com/services/T0/B0/X", True),
        ("PARTITION_KEY", "tenant", False),
        ("TOKEN_TTL", "3600", False),
        ("DB_PASS", "var.db_pass", False),
        ("API_URL", "https://example.com", False),
    ],
)
def test_codebuild_name_and_value_heuristics(name, value, expected):
    conf = {"environment": [{"environment_variable": [{"name": [name], "value": [value]}]}]}
    assert _scan_codebuild_env(conf) is expected
