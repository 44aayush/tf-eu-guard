"""Gap-closing tests for T-01..T-07 (coverage audit).

Covers: Kubernetes ``checkov.io/skip`` through real Checkov, suppressed findings
combined with ``--framework`` for every output format, ``--allowed-regions``
edge cases, Backup ARN / ECR destination residency, mixed ``ENC[`` Secrets, UNC
working directories and the UTF-8 stream reconfiguration.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.cli_helpers import run_cli
from tf_eu_guard.checks.regions_conf import collect_regions
from tf_eu_guard.cli import _ensure_utf8_streams
from tf_eu_guard.constants import EXIT_FINDINGS, EXIT_OK
from tf_eu_guard.residency import parse_allowed_regions

SKIPPED_FIXTURE = "tests/fixtures/checkov-skipped-tf.json"
K8S_SKIP = "tests/fixtures/k8s-skip"
MIXED_SECRET = "tests/fixtures/secret-shapes-k8s-mixed"
BACKUP_ECR = "tests/fixtures/residency-backup-ecr"


def _json_findings(capsys) -> list[dict]:
    return json.loads(capsys.readouterr().out)


# --- T-01: Kubernetes checkov.io/skip through real Checkov -----------------------


def test_k8s_checkov_io_skip_is_reported_as_suppressed(monkeypatch, tmp_path, capsys, repo_root):
    rc = run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / K8S_SKIP),
        "--iac-type",
        "kubernetes",
        "--output",
        "json",
    )
    entries = {e["check_id"]: e for e in _json_findings(capsys)}
    assert entries["CKV_K8S_8"]["suppressed"] is True
    assert entries["CKV_K8S_8"]["suppression_reason"] == "liveness probe handled by the sidecar"
    # An annotation without "=reason" is suppressed with no stated reason.
    assert entries["CKV_K8S_9"]["suppressed"] is True
    assert entries["CKV_K8S_9"]["suppression_reason"] is None
    # Checks not named in the annotations stay active.
    assert any(not e["suppressed"] for e in entries.values())
    assert rc == EXIT_OK  # default gate: suppressed findings never fail the run


def test_k8s_skip_fail_on_suppressed_and_dev_report(monkeypatch, tmp_path, capsys, repo_root):
    target = str(repo_root / K8S_SKIP)
    rc = run_cli(monkeypatch, tmp_path, target, "--iac-type", "kubernetes", "--output", "dev")
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "Suppressed by inline comment" in out
    assert "liveness probe handled by the sidecar" in out
    rc = run_cli(
        monkeypatch,
        tmp_path,
        target,
        "--iac-type",
        "kubernetes",
        "--output",
        "json",
        "--fail-on-suppressed",
    )
    assert rc == EXIT_FINDINGS


# --- T-01: suppressed findings x --framework for every output format -----------


@pytest.fixture
def skipped_only(repo_root, tmp_path) -> str:
    data = json.loads((repo_root / SKIPPED_FIXTURE).read_text())
    data["results"]["failed_checks"] = []
    path = tmp_path / "only-skipped.json"
    path.write_text(json.dumps(data))
    return str(path)


def _render(monkeypatch, tmp_path, capsys, source, output, framework) -> str:
    args = ["--checkov-json", source, "--framework", framework]
    if output == "dev":
        run_cli(monkeypatch, tmp_path, *args)
        return capsys.readouterr().out
    if output == "sarif":
        run_cli(monkeypatch, tmp_path, *args, "--output", "sarif")
        return capsys.readouterr().out
    if output in ("security", "auditor"):
        out_file = tmp_path / f"{output}-{framework}.html"
        run_cli(monkeypatch, tmp_path, *args, "--output", output, "--output-file", str(out_file))
        return out_file.read_text()
    # dev-html is only produced by --output all
    out_dir = tmp_path / f"all-{framework}"
    run_cli(monkeypatch, tmp_path, *args, "--output", "all", "--output-dir", str(out_dir))
    return next(out_dir.glob("dev_report_*.html")).read_text()


@pytest.mark.parametrize("output", ["dev", "security", "auditor", "dev-html", "sarif"])
def test_framework_filter_applies_to_suppressed_in_every_format(
    monkeypatch, tmp_path, capsys, skipped_only, output
):
    # CKV_AWS_18: NIS2 only. CKV_AWS_145: NIS2 and GDPR.
    nis2 = _render(monkeypatch, tmp_path, capsys, skipped_only, output, "nis2")
    assert "CKV_AWS_18" in nis2 and "CKV_AWS_145" in nis2
    gdpr = _render(monkeypatch, tmp_path, capsys, skipped_only, output, "gdpr")
    assert "CKV_AWS_145" in gdpr
    assert "CKV_AWS_18" not in gdpr.replace("CKV_AWS_145", "")


# --- T-06: --allowed-regions edge cases ---------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("EU-WEST-1", ("eu-west-1",)),
        ("  eu-west-1  ", ("eu-west-1",)),
        ("eu-west-1,eu-west-1,EU-West-1", ("eu-west-1",)),
        ("eu-west-1,,eu-north-1,", ("eu-north-1", "eu-west-1")),
        (",eu-west-1", ("eu-west-1",)),
        ("eu-west-1,\teu-north-1", ("eu-north-1", "eu-west-1")),
        ("eusc-de-east-1", ("eusc-de-east-1",)),
    ],
)
def test_parse_allowed_regions_accepts(text, expected):
    assert parse_allowed_regions(text) == expected


@pytest.mark.parametrize(
    "text", ["", " ", ",", " , , ", "eu west", "-eu-west-1", "eu_west_1", "eu-west-1;rm", "eu/west"]
)
def test_parse_allowed_regions_rejects(text):
    with pytest.raises(ValueError):
        parse_allowed_regions(text)


def test_custom_policy_live_with_messy_allowlist(monkeypatch, tmp_path, capsys, repo_root):
    """Mixed case, whitespace, duplicates and empty items all reach the checks intact."""
    run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / BACKUP_ECR),
        "--output",
        "json",
        "--residency-policy",
        "custom",
        "--allowed-regions",
        " US-East-2 , us-west-2,us-west-2,,",
    )
    by_check: dict[str, set[str]] = {}
    for f in _json_findings(capsys):
        by_check.setdefault(f["check_id"], set()).add(f["resource"])
    # The eu-central-1 provider is outside the custom allowlist.
    assert by_check["EUGUARD_POLICY_001"] == {"aws.default"}
    # Offshore destinations are now allowed; the EU ones are not.
    assert by_check["EUGUARD_POLICY_002"] == {
        "aws_backup_plan.inside_eu",
        "aws_ecr_replication_configuration.inside_eu",
    }


# --- T-07: Backup ARN and ECR destination -----------------------------------------


def _backup(arn) -> list:
    conf = {"rule": [{"copy_action": [{"destination_vault_arn": [arn]}]}]}
    return collect_regions("aws_backup_plan", conf)


@pytest.mark.parametrize(
    ("arn", "region"),
    [
        ("arn:aws:backup:us-east-2:123456789012:backup-vault:v", "us-east-2"),
        ("ARN:AWS:BACKUP:US-EAST-2:123456789012:BACKUP-VAULT:V".lower(), "us-east-2"),
        ("arn:aws-us-gov:backup:us-gov-west-1:123:backup-vault:v", "us-gov-west-1"),
        ("arn:aws-cn:backup:cn-north-1:123:backup-vault:v", "cn-north-1"),
        ("  arn:aws:backup:eu-west-1:123:backup-vault:v  ", "eu-west-1"),
    ],
)
def test_backup_arn_resolved(arn, region):
    refs = _backup(arn)
    assert [r.region for r in refs] == [region]
    assert refs[0].key.endswith("destination_vault_arn")


@pytest.mark.parametrize(
    "arn",
    [
        "var.vault_arn",
        "aws_backup_vault.dr.arn",
        "arn:aws:backup:${var.region}:123:backup-vault:v",
        "${aws_backup_vault.dr.arn}",
        "arn:aws:backup::123:backup-vault:v",
        "arn:aws:s3:::bucket",
        "not-an-arn",
        "",
        None,
        42,
    ],
)
def test_backup_arn_unresolved_or_foreign_names_no_region(arn):
    assert _backup(arn) == []


def test_backup_multiple_rules_and_copy_actions_keep_distinct_keys():
    conf = {
        "rule": [
            {
                "copy_action": [
                    {"destination_vault_arn": ["arn:aws:backup:us-east-1:1:backup-vault:a"]},
                    {"destination_vault_arn": ["arn:aws:backup:eu-west-1:1:backup-vault:b"]},
                ]
            },
            {
                "copy_action": [
                    {"destination_vault_arn": ["arn:aws:backup:ap-south-1:1:backup-vault:c"]}
                ]
            },
        ]
    }
    refs = collect_regions("aws_backup_plan", conf)
    assert [r.region for r in refs] == ["us-east-1", "eu-west-1", "ap-south-1"]
    assert len({r.key for r in refs}) == 3


def test_backup_arn_attribute_ignored_on_other_resource_types():
    conf = {
        "rule": [{"copy_action": [{"destination_vault_arn": ["arn:aws:backup:us-east-2:1:x:y"]}]}]
    }
    assert collect_regions("aws_s3_bucket", conf) == []


def test_ecr_destinations_multiple_and_other_type_ignored():
    conf = {
        "replication_configuration": [
            {
                "rule": [
                    {"destination": [{"region": ["us-west-2"]}, {"region": ["eu-north-1"]}]},
                ]
            }
        ]
    }
    assert [r.region for r in collect_regions("aws_ecr_replication_configuration", conf)] == [
        "us-west-2",
        "eu-north-1",
    ]
    assert collect_regions("aws_ecr_repository", conf) == []
    # Unresolved / empty destination region names nothing.
    empty = {"replication_configuration": [{"rule": [{"destination": [{"region": [""]}]}]}]}
    assert collect_regions("aws_ecr_replication_configuration", empty) == []


def test_backup_and_ecr_residency_live(monkeypatch, tmp_path, capsys, repo_root):
    run_cli(monkeypatch, tmp_path, str(repo_root / BACKUP_ECR), "--output", "json")
    by_check: dict[str, set[str]] = {}
    for f in _json_findings(capsys):
        by_check.setdefault(f["check_id"], set()).add(f["resource"])
    offshore = {"aws_backup_plan.offshore", "aws_ecr_replication_configuration.offshore"}
    assert by_check["EUGUARD_POLICY_002"] == offshore
    assert by_check["EUGUARD_GDPR_003"] == offshore
    # Unresolved ARN and EU destinations produce nothing under the default policy.
    flagged = by_check["EUGUARD_POLICY_002"] | by_check["EUGUARD_GDPR_003"]
    assert not any("unresolved" in r or "inside_eu" in r for r in flagged)


# --- T-05: Secret mixing ENC[ and plain values (real Checkov) ------------------------


def test_k8s_secret_mixing_enc_and_plain_live(monkeypatch, tmp_path, capsys, repo_root):
    run_cli(
        monkeypatch,
        tmp_path,
        str(repo_root / MIXED_SECRET),
        "--iac-type",
        "kubernetes",
        "--output",
        "json",
    )
    flagged = [f for f in _json_findings(capsys) if f["check_id"] == "EUGUARD_NIS2_002"]
    assert [f["resource"] for f in flagged] == ["Secret.default.mixed"]


# --- T-02: UNC working directory -----------------------------------------------------


def _fake_drive(monkeypatch, mapping):
    def splitdrive(path):
        path = str(path)
        for prefix, drive in mapping.items():
            if path.startswith(prefix):
                return drive, path[len(prefix) :]
        return "", path

    monkeypatch.setattr("tf_eu_guard.checkov.process.os.path.splitdrive", splitdrive)


UNC = "\\\\fileserver\\share"


def test_trusted_workdir_uses_unc_share_root(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    default = Path(process.sysconfig.get_path("purelib"))
    _fake_drive(monkeypatch, {str(default): "C:", str(tmp_path): UNC})
    workdir = process.trusted_checkov_workdir(tmp_path)
    assert str(workdir).startswith(UNC)
    assert workdir == Path(UNC + os.sep)
    assert not str(workdir).startswith(str(tmp_path))


def test_trusted_workdir_keeps_default_on_same_unc_share_any_case(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    default = Path(process.sysconfig.get_path("purelib"))
    _fake_drive(monkeypatch, {str(default): UNC, str(tmp_path): UNC.upper()})
    assert process.trusted_checkov_workdir(tmp_path) == default


def test_trusted_workdir_unc_vs_different_unc_share(monkeypatch, tmp_path):
    from tf_eu_guard.checkov import process

    default = Path(process.sysconfig.get_path("purelib"))
    other = "\\\\fileserver\\other"
    _fake_drive(monkeypatch, {str(default): UNC, str(tmp_path): other})
    assert process.trusted_checkov_workdir(tmp_path) == Path(other + os.sep)


# --- T-03: UTF-8 stream reconfiguration (stdout and stderr) ---------------------------


class _Stream:
    def __init__(self, encoding, error=None, has_reconfigure=True):
        self.encoding = encoding
        self.calls = []
        self._error = error
        if has_reconfigure:
            self.reconfigure = self._reconfigure

    def _reconfigure(self, **kwargs):
        if self._error:
            raise self._error
        self.calls.append(kwargs)


def test_reconfigures_both_stdout_and_stderr(monkeypatch):
    out, err = _Stream("cp1252"), _Stream("ascii")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    _ensure_utf8_streams()
    assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.calls == [{"encoding": "utf-8", "errors": "replace"}]


@pytest.mark.parametrize("encoding", ["utf-8", "UTF-8", "utf8", "UTF_8"])
def test_utf8_streams_are_left_alone(monkeypatch, encoding):
    out, err = _Stream(encoding), _Stream(encoding)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    _ensure_utf8_streams()
    assert out.calls == [] and err.calls == []


def test_stdout_utf8_stderr_other_only_stderr_reconfigured(monkeypatch):
    out, err = _Stream("utf-8"), _Stream("cp437")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    _ensure_utf8_streams()
    assert out.calls == []
    assert len(err.calls) == 1


@pytest.mark.parametrize("error", [ValueError("closed"), OSError("bad"), None])
def test_reconfigure_failures_and_missing_method_are_tolerated(monkeypatch, error):
    broken = _Stream("cp1252", error=error, has_reconfigure=error is not None)
    plain = _Stream(None, has_reconfigure=False)  # no encoding, no reconfigure
    monkeypatch.setattr(sys, "stdout", broken)
    monkeypatch.setattr(sys, "stderr", plain)
    _ensure_utf8_streams()  # must not raise


def test_dev_report_survives_ascii_redirect_end_to_end(tmp_path, repo_root):
    """A real process whose stdout/stderr encode as ASCII still prints the report."""
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
    env["PYTHONIOENCODING"] = "ascii"
    out_file = tmp_path / "out.txt"
    err_file = tmp_path / "err.txt"
    with out_file.open("wb") as out, err_file.open("wb") as err:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from tf_eu_guard.cli import main; "
                "sys.argv = ['tf-eu-guard', *sys.argv[1:]]; sys.exit(main())",
                "scan",
                "--checkov-json",
                str(repo_root / SKIPPED_FIXTURE),
                "--output",
                "dev",
            ],
            cwd=tmp_path,
            env={**env, "PYTHONPATH": str(repo_root)},
            stdout=out,
            stderr=err,
            check=False,
        )
    assert proc.returncode == EXIT_OK, err_file.read_text(errors="replace")
    assert "═" in out_file.read_text(encoding="utf-8")


# --- T-01: reporting helpers and edge branches -------------------------------------


def _item(**overrides):
    from tf_eu_guard.reporting.suppressed import SuppressedItem

    values = {
        "check_id": "CKV_X_1",
        "check_name": "n",
        "resource": "r.a",
        "file_path": "/m.tf",
        "file_line_range": [3, 8],
        "reason": None,
        "mapped": False,
    }
    values.update(overrides)
    return SuppressedItem(**values)


@pytest.mark.parametrize(
    ("line_range", "lines", "location"),
    [
        ([3, 8], "3-8", "/m.tf:3-8"),
        ([5], "5", "/m.tf:5"),
        ([0, 4], "0-4", "/m.tf:0-4"),
        ([0], None, "/m.tf"),
        ([0, 0], None, "/m.tf"),
        ([], None, "/m.tf"),
    ],
)
def test_suppressed_item_line_formats(line_range, lines, location):
    item = _item(file_line_range=line_range)
    assert item.lines == lines
    assert item.location == location


def test_suppressed_html_empty_and_escaped():
    from tf_eu_guard.reporting.suppressed import suppressed_html

    assert suppressed_html([]) == ""
    html = suppressed_html([_item(check_name="<b>x</b>", reason="a&b")])
    assert "&lt;b&gt;" in html and "a&amp;b" in html and "<b>x</b>" not in html
    assert "unmapped" in html and "(1)" in html


def test_malformed_skipped_check_is_a_runtime_error_not_a_crash():
    from tf_eu_guard.checkov.json import validate_scan_output
    from tf_eu_guard.checkov.types import CheckovRuntimeError

    data = {
        "check_type": "terraform",
        "summary": {"parsing_errors": 0},
        "results": {"failed_checks": [], "skipped_checks": [{"check_id": "CKV_X_1"}]},
    }
    with pytest.raises(CheckovRuntimeError, match="malformed finding"):
        validate_scan_output(data, "terraform")


def test_dev_report_suppressed_with_only_unmapped_active(capsys):
    from tf_eu_guard.reporting.dev_report import generate_dev_report

    generate_dev_report(
        [],
        unmapped_count=2,
        suppressed_unmapped=[
            {
                "check_id": "CKV_X_9",
                "check_name": "n",
                "resource": "r.a",
                "file_path": "/m.tf",
                "file_line_range": [1, 2],
                "suppression_reason": "because",
            }
        ],
    )
    out = capsys.readouterr().out
    assert "2 unmapped" in out
    assert "Suppressed by inline comment (1)" in out
    assert "CKV_X_9" in out and "because" in out


def test_html_reports_file_output_includes_suppressed_and_is_utf8(tmp_path, repo_root):
    """T-03: suppressed section with non-ASCII text is written as UTF-8 by every file report."""
    from tf_eu_guard.checkov.json import extract_skipped_checks
    from tf_eu_guard.models import EnrichedFinding
    from tf_eu_guard.reporting.auditor_report import generate_auditor_report
    from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report
    from tf_eu_guard.reporting.security_report import generate_security_report

    skipped = extract_skipped_checks(json.loads((repo_root / SKIPPED_FIXTURE).read_text()))[0]
    finding = EnrichedFinding(
        check_id=skipped["check_id"],
        check_name=skipped["check_name"],
        resource=skipped["resource"],
        file_path=skipped["file_path"],
        file_line_range=skipped["file_line_range"],
        guideline=None,
        articles=[],
        severity=None,
        suppressed=True,
        suppression_reason="café → ok",
    )
    for name, generator in (
        ("dev", generate_dev_html_report),
        ("security", generate_security_report),
        ("auditor", generate_auditor_report),
    ):
        out_path = tmp_path / f"{name}.html"
        generator([], output_path=out_path, suppressed=[finding])
        text = out_path.read_bytes().decode("utf-8")
        assert "Suppressed by inline comment (1)" in text, name
        assert "café → ok" in text, name


def test_sarif_stdout_notes_unmapped_on_stderr_only(monkeypatch, tmp_path, capsys, repo_root):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / "tests/fixtures/checkov-unmapped-tf.json"),
        "--output",
        "sarif",
    )
    captured = capsys.readouterr()
    json.loads(captured.out)  # stdout stays pure SARIF
    assert "unmapped Checkov finding(s) included" in captured.err


# --- T-04 / T-05: defensive shapes of the shared secret predicates -----------------------


@pytest.mark.parametrize("value", [None, 5, True, [], {}, "", "   "])
def test_secret_predicates_reject_non_strings_and_blank(value):
    from tf_eu_guard.checks.nis2.secret_names import (
        has_embedded_credentials,
        is_literal_env_value,
        is_literal_secret_value,
        is_reference_value,
    )

    assert is_reference_value(value) is False
    assert is_literal_secret_value(value) is False
    assert has_embedded_credentials(value) is False
    assert is_literal_env_value(value) is False


@pytest.mark.parametrize("value", ["${var.a", "prefix-${var.a", "${", "${var.a{"])
def test_unbalanced_interpolation_is_a_literal(value):
    from tf_eu_guard.checks.nis2.secret_names import is_literal_secret_value, is_reference_value

    assert is_reference_value(value) is False
    assert is_literal_secret_value(value) is True


def test_empty_interpolation_body_is_not_a_reference():
    from tf_eu_guard.checks.nis2.secret_names import is_reference_value

    assert is_reference_value("${}") is False
    assert is_reference_value("${  }") is False


def test_plain_url_without_credentials_exempt_but_with_credentials_flagged():
    from tf_eu_guard.checks.nis2.secret_names import is_literal_env_value

    assert is_literal_env_value("https://api.example.com/v1") is False
    assert is_literal_env_value("http://api.example.com") is False
    assert is_literal_env_value("https://user:tok3n@api.example.com") is True
    assert is_literal_env_value("hunter2") is True


def test_k8s_container_env_defensive_shapes():
    from checkov.common.models.enums import CheckResult

    from tf_eu_guard.checks.k8s.secrets_in_code import K8sContainerEnvHardcodedSecrets

    check = K8sContainerEnvHardcodedSecrets()
    check.entity_type = "containers"
    assert check.scan_container_conf({}, {}) == CheckResult.PASSED
    assert check.scan_container_conf({}, {"env": "nope"}) == CheckResult.PASSED
    # Non-dict entries and non-string values are skipped, not crashed on.
    mixed = ["junk", {"name": "DB_PASS", "value": 5}, {"name": "DB_PASS", "value": True}]
    assert check.scan_container_conf({}, {"env": mixed}) == CheckResult.PASSED
    # A real literal after the junk is still found.
    mixed.append({"name": "DB_PASS", "value": "Sup3rS3cret!"})
    assert check.scan_container_conf({}, {"env": mixed}) == CheckResult.FAILED


def test_codebuild_env_defensive_shapes():
    from checkov.common.models.enums import CheckResult

    from tf_eu_guard.checks.nis2.secrets_in_code import HardcodedSecrets

    check = HardcodedSecrets()
    check.entity_type = "aws_codebuild_project"
    assert check.scan_resource_conf({"environment": ["junk"]}) == CheckResult.PASSED
    assert check.scan_resource_conf({}) == CheckResult.PASSED
    nested = {
        "environment": [
            {
                "environment_variable": [
                    [{"name": ["DB_PASS"], "value": ["Sup3rS3cret!"], "type": ["PLAINTEXT"]}]
                ]
            }
        ]
    }
    assert check.scan_resource_conf(nested) == CheckResult.FAILED
    # A secret-manager typed variable is a reference, not plaintext.
    nested["environment"][0]["environment_variable"][0][0]["type"] = ["SECRETS_MANAGER"]
    assert check.scan_resource_conf(nested) == CheckResult.PASSED


# --- T-06 / T-07: provider-level residency defensive shapes ------------------------------


@pytest.mark.parametrize("region", [None, "", "   ", 5, ["", ""]])
def test_provider_region_unset_or_malformed_is_unknown(region):
    from checkov.common.models.enums import CheckResult

    from tf_eu_guard.checks.gdpr.data_residency import ThirdCountryTransferReview

    conf = {} if region is None else {"region": region if isinstance(region, list) else [region]}
    assert ThirdCountryTransferReview().scan_provider_conf(conf) == CheckResult.UNKNOWN


def test_collect_regions_nested_list_without_dicts_and_blank_regions():
    # Non-dict list members and blank / non-string region values are ignored.
    assert collect_regions("aws_s3_bucket", {"region": [["x"]]}) == []
    assert collect_regions("aws_s3_bucket", {"region": ["  "]}) == []
    assert collect_regions("aws_dynamodb_table", {"replica": ["junk", {"region_name": [""]}]}) == []
    assert collect_regions("aws_dynamodb_table", {"replica": "junk"}) == []
    refs = collect_regions("aws_s3_bucket", {"region": ["  US-East-1 "]})
    assert [r.region for r in refs] == ["us-east-1"]
