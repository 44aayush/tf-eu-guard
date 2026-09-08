"""Tests for SARIF 2.1.0 output.

The built document is validated against the official OASIS SARIF 2.1.0
JSON Schema (vendored at ``tests/schemas/sarif-2.1.0.json``), not just
spot-checked — a SARIF file that merely "looks right" can still be
rejected by GitHub Code Scanning.
"""

import json
from pathlib import Path

import pytest

from tf_eu_guard.models import (
    ArticleReference,
    EnrichedFinding,
    Framework,
    Severity,
)
from tf_eu_guard.reporting.sarif_report import build_sarif, sarif_level

SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-2.1.0.json"

jsonschema = pytest.importorskip("jsonschema", reason="jsonschema not installed")


def make_finding(**overrides) -> EnrichedFinding:
    defaults = dict(
        check_id="CKV_AWS_18",
        check_name="Ensure S3 bucket has encryption enabled",
        resource="aws_s3_bucket.data",
        file_path="main.tf",
        file_line_range=[10, 20],
        guideline="https://docs.bridgecrew.io/docs/s3-encryption",
        articles=[
            ArticleReference(
                Framework.GDPR,
                "Art. 32(1)(a)",
                "Pseudonymisation and encryption of personal data",
            )
        ],
        risk_explanation="Unencrypted bucket.",
        remediation="Enable encryption.",
        severity=Severity.HIGH,
    )
    defaults.update(overrides)
    return EnrichedFinding(**defaults)


@pytest.fixture(scope="module")
def sarif_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator(sarif_schema):
    return jsonschema.Draft7Validator(sarif_schema)


@pytest.fixture
def findings():
    return [
        make_finding(),
        make_finding(
            check_id="EUGUARD_GDPR_001",
            resource="aws.provider",
            severity=Severity.MEDIUM,
        ),
        # Same check_id as the first finding on another resource: one rule,
        # two results.
        make_finding(resource="aws_s3_bucket.other"),
    ]


def test_level_mapping():
    assert sarif_level(Severity.CRITICAL) == "error"
    assert sarif_level(Severity.HIGH) == "error"
    assert sarif_level(Severity.MEDIUM) == "warning"
    assert sarif_level(Severity.LOW) == "note"
    assert sarif_level(Severity.INFO) == "note"


def test_document_validates_against_sarif_schema(validator, findings):
    document = build_sarif(findings, version="1.2.3", target="examples/vulnerable-aws")
    validator.validate(document)


def test_document_validates_with_unmapped_findings(validator, findings):
    unmapped = [{
        "check_id": "CKV_UNMAPPED_999",
        "check_name": "A check with no EU mapping",
        "resource": "aws_example.thing",
        "file_path": "other.tf",
        "file_line_range": [3, 4],
    }]
    document = build_sarif(findings, unmapped=unmapped)
    validator.validate(document)


def test_document_validates_when_empty(validator):
    validator.validate(build_sarif([]))


def test_rules_deduplicated_and_referenced(findings):
    document = build_sarif(findings)
    run = document["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["CKV_AWS_18", "EUGUARD_GDPR_001"]
    for result in run["results"]:
        assert result["ruleId"] == rule_ids[result["ruleIndex"]]
        assert result["ruleIndex"] < len(rule_ids)


def test_result_fields_carry_regulatory_metadata(findings):
    result = build_sarif(findings)["runs"][0]["results"][0]
    assert result["ruleId"] == "CKV_AWS_18"
    assert result["level"] == "error"
    assert result["message"]["text"] == "Unencrypted bucket."
    (location,) = result["locations"]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "main.tf"
    assert location["physicalLocation"]["region"] == {"startLine": 10, "endLine": 20}
    properties = result["properties"]
    assert properties["articles"] == ["GDPR Art. 32(1)(a)"]
    assert properties["severity"] == "HIGH"
    assert properties["remediation"] == "Enable encryption."
    assert properties["mapped"] is True
    assert properties["resource"] == "aws_s3_bucket.data"


def test_rule_carries_regulatory_metadata(findings):
    rules = build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    (rule,) = [r for r in rules if r["id"] == "CKV_AWS_18"]
    assert rule["shortDescription"]["text"].startswith("Ensure S3 bucket")
    assert rule["fullDescription"]["text"] == "Unencrypted bucket."
    assert rule["helpUri"] == "https://docs.bridgecrew.io/docs/s3-encryption"
    assert rule["properties"]["articles"] == ["GDPR Art. 32(1)(a)"]
    assert rule["properties"]["remediation"] == "Enable encryption."
    assert rule["properties"]["mapped"] is True


def test_unmapped_results_are_note_level_and_tagged(validator):
    unmapped = [{
        "check_id": "CKV_UNMAPPED_999",
        "check_name": "A check with no EU mapping",
        "resource": "aws_example.thing",
        "file_path": "other.tf",
        "file_line_range": [3, 4],
    }]
    document = build_sarif([], unmapped=unmapped)
    validator.validate(document)
    run = document["runs"][0]
    (result,) = run["results"]
    assert result["level"] == "note"
    assert result["properties"]["mapped"] is False
    assert "no current EU regulatory mapping" in result["message"]["text"]
    (rule,) = run["tool"]["driver"]["rules"]
    assert rule["properties"]["mapped"] is False


def test_malformed_line_range_degrades_to_file_location(validator):
    finding = make_finding(file_line_range=[0, 0])
    document = build_sarif([finding])
    validator.validate(document)
    (location,) = document["runs"][0]["results"][0]["locations"]
    assert "region" not in location["physicalLocation"]


def test_driver_identifies_the_tool(findings):
    driver = build_sarif(findings, version="9.9.9")["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tf-eu-guard"
    assert driver["version"] == "9.9.9"
    assert driver["informationUri"].startswith("https://")


def test_cli_sarif_output_validates(monkeypatch, tmp_path, repo_root, capsys, validator):
    """End-to-end: --output sarif produces schema-valid SARIF on stdout."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tf-eu-guard", "scan",
            "--checkov-json", str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json"),
            "--output", "sarif",
        ],
    )
    from tf_eu_guard.cli import main

    assert main() == 0
    document = json.loads(capsys.readouterr().out)
    validator.validate(document)
    run = document["runs"][0]
    assert run["results"], "fixture should produce mapped findings"
    assert any(
        "Art." in article
        for result in run["results"]
        for article in result["properties"]["articles"]
    )


def test_cli_sarif_output_file(monkeypatch, tmp_path, repo_root, capsys, validator):
    out_file = tmp_path / "results.sarif"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tf-eu-guard", "scan",
            "--checkov-json", str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json"),
            "--output", "sarif", "--output-file", str(out_file),
        ],
    )
    from tf_eu_guard.cli import main

    assert main() == 0
    document = json.loads(out_file.read_text(encoding="utf-8"))
    validator.validate(document)
    assert "SARIF report written" in capsys.readouterr().out
