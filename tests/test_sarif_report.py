"""Tests for SARIF 2.1.0 output.

The built document is validated against the official OASIS SARIF 2.1.0
JSON Schema (vendored at ``tests/schemas/sarif-2.1.0.json``), not just
spot-checked — a SARIF file that merely "looks right" can still be
rejected by GitHub Code Scanning.
"""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest

from tf_eu_guard.cli import main
from tf_eu_guard.models import (
    ArticleReference,
    EnrichedFinding,
    Framework,
    Severity,
)
from tf_eu_guard.reporting.sarif_report import build_sarif, sarif_level

SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-2.1.0.json"

jsonschema = pytest.importorskip("jsonschema", reason="jsonschema not installed")


_DEFAULT_LINE_RANGE = object()


def make_finding(
    check_id: str = "CKV_AWS_18",
    check_name: str = "Ensure S3 bucket has encryption enabled",
    resource: str = "aws_s3_bucket.data",
    file_path: str = "main.tf",
    file_line_range: Any = _DEFAULT_LINE_RANGE,
    guideline: str | None = "https://docs.bridgecrew.io/docs/s3-encryption",
    articles: list[ArticleReference] | None = None,
    risk_explanation: str = "Unencrypted bucket.",
    remediation: str = "Enable encryption.",
    severity: Severity = Severity.HIGH,
) -> EnrichedFinding:
    if file_line_range is _DEFAULT_LINE_RANGE:
        file_line_range = [10, 20]
    if articles is None:
        articles = [
            ArticleReference(
                Framework.GDPR,
                "Art. 32(1)(a)",
                "Pseudonymisation and encryption of personal data",
            )
        ]
    return EnrichedFinding(
        check_id=check_id,
        check_name=check_name,
        resource=resource,
        file_path=file_path,
        file_line_range=file_line_range,
        guideline=guideline,
        articles=articles,
        risk_explanation=risk_explanation,
        remediation=remediation,
        severity=severity,
    )


@pytest.fixture(scope="module")
def sarif_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator(sarif_schema):
    return jsonschema.Draft7Validator(sarif_schema, format_checker=jsonschema.FormatChecker())


@pytest.fixture
def findings():
    return [
        make_finding(),
        make_finding(
            check_id="EUGUARD_GDPR_002",
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
    unmapped = [
        {
            "check_id": "CKV_UNMAPPED_999",
            "check_name": "A check with no EU mapping",
            "resource": "aws_example.thing",
            "file_path": "other.tf",
            "file_line_range": [3, 4],
        }
    ]
    document = build_sarif(findings, unmapped=unmapped)
    validator.validate(document)


def test_document_validates_when_empty(validator):
    validator.validate(build_sarif([]))


def test_rules_deduplicated_and_referenced(findings):
    document = build_sarif(findings)
    run = document["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["CKV_AWS_18", "EUGUARD_GDPR_002"]
    for result in run["results"]:
        assert result["ruleId"] == rule_ids[result["ruleIndex"]]
        assert result["ruleIndex"] < len(rule_ids)


def test_sarif_is_byte_stable_and_rule_indexes_follow_sorted_rules(findings):
    """A Checkov result permutation must produce identical serialized SARIF."""
    unmapped = [
        {
            "check_id": "CKV_UNMAPPED_002",
            "check_name": "Unmapped later file",
            "resource": "aws_example.later",
            "file_path": "z.tf",
            "file_line_range": [2, 3],
        },
        {
            "check_id": "CKV_UNMAPPED_001",
            "check_name": "Unmapped earlier file",
            "resource": "aws_example.earlier",
            "file_path": "a.tf",
            "file_line_range": [2, 3],
        },
    ]
    first = build_sarif(findings, unmapped=unmapped, version="1.2.3")
    second = build_sarif(
        list(reversed(findings)),
        unmapped=list(reversed(unmapped)),
        version="1.2.3",
    )
    first_bytes = json.dumps(first, indent=2, sort_keys=True).encode()
    second_bytes = json.dumps(second, indent=2, sort_keys=True).encode()
    assert first_bytes == second_bytes

    run = first["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert result["ruleId"] == rules[result["ruleIndex"]]["id"]


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


@pytest.mark.parametrize(
    "guideline",
    ["javascript:alert(1)", "data:text/html,alert(1)", "not-a-url", "https://", ""],
)
def test_unsafe_guideline_is_omitted_from_sarif(guideline):
    document = build_sarif([make_finding(guideline=guideline)])
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    (result,) = document["runs"][0]["results"]
    assert "helpUri" not in rule
    assert "guideline" not in result["properties"]


def test_rule_carries_regulatory_metadata(findings):
    rules = build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    (rule,) = [r for r in rules if r["id"] == "CKV_AWS_18"]
    assert rule["shortDescription"]["text"].startswith("Ensure S3 bucket")
    assert rule["fullDescription"]["text"] == "Unencrypted bucket."
    assert rule["helpUri"] == "https://docs.bridgecrew.io/docs/s3-encryption"
    assert rule["properties"]["articles"] == ["GDPR Art. 32(1)(a)"]
    assert rule["properties"]["remediation"] == "Enable encryption."
    assert rule["properties"]["mapped"] is True


def test_build_sarif_array_baseline_omits_new_state(validator):
    known = {
        "check_id": "CKV_U_1",
        "resource": "a.b",
        "file_path": "a.tf",
        "file_line_range": [1, 2],
    }
    fresh = {
        "check_id": "CKV_U_2",
        "resource": "c.d",
        "file_path": "c.tf",
        "file_line_range": [1, 2],
    }
    document = build_sarif(
        [], unmapped=[fresh], baselined_unmapped=[known], baseline_covers_unmapped=False
    )
    validator.validate(document)
    states = {r["ruleId"]: r.get("baselineState") for r in document["runs"][0]["results"]}
    assert states == {"CKV_U_1": "unchanged", "CKV_U_2": None}


def test_unmapped_results_are_note_level_and_tagged(validator):
    unmapped = [
        {
            "check_id": "CKV_UNMAPPED_999",
            "check_name": "A check with no EU mapping",
            "resource": "aws_example.thing",
            "file_path": "other.tf",
            "file_line_range": [3, 4],
        }
    ]
    document = build_sarif([], unmapped=unmapped)
    validator.validate(document)
    run = document["runs"][0]
    (result,) = run["results"]
    assert result["level"] == "note"
    assert result["properties"]["mapped"] is False
    assert result["properties"]["resource"] == "aws_example.thing"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ("other.tf")
    assert "remediation" not in result["properties"]
    assert "no current EU regulatory mapping" in result["message"]["text"]
    (rule,) = run["tool"]["driver"]["rules"]
    assert rule["properties"]["mapped"] is False
    assert rule["shortDescription"]["text"] == "A check with no EU mapping"
    assert "remediation" not in rule["properties"]


def test_sarif_rejects_empty_rule_ids():
    with pytest.raises(ValueError, match="rule IDs must be non-empty strings"):
        build_sarif([make_finding(check_id="")])

    with pytest.raises(ValueError, match="rule IDs must be non-empty strings"):
        build_sarif([], unmapped=[{"check_id": None}])


@pytest.mark.parametrize(
    "line_range",
    [
        [0, 0],
        ["bad", 4],
        ["4", "5"],
        [-1, 4],
        [4, -1],
        [5, 4],
        [4],
        [],
        None,
    ],
)
def test_malformed_line_range_degrades_to_file_location(validator, line_range):
    finding = make_finding(file_line_range=line_range)
    document = build_sarif([finding])
    validator.validate(document)
    (location,) = document["runs"][0]["results"][0]["locations"]
    assert "region" not in location["physicalLocation"]


def test_valid_line_range_and_path_are_uri_safe(validator):
    finding = make_finding(file_path="src/my file#1.tf", file_line_range=[4, 5])
    document = build_sarif([finding])
    validator.validate(document)
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "src/my%20file%231.tf"
    assert location["physicalLocation"]["region"] == {"startLine": 4, "endLine": 5}


def test_checkov_scan_relative_path_becomes_repository_relative(validator, tmp_path):
    repo = tmp_path / "checkout"
    scan = repo / "examples" / "vulnerable-aws"
    scan.mkdir(parents=True)

    document = build_sarif(
        [make_finding(file_path="/iam.tf")],
        scan_root=scan,
        repository_root=repo,
    )
    validator.validate(document)
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == (
        "examples/vulnerable-aws/iam.tf"
    )


def test_path_outside_repository_is_retained_without_unsafe_location(validator, tmp_path):
    repo = tmp_path / "checkout"
    scan = repo / "examples" / "vulnerable-aws"
    scan.mkdir(parents=True)
    unmapped = [
        {
            "check_id": "CKV_UNMAPPED_999",
            "check_name": "A check with no EU mapping",
            "resource": "aws_example.thing",
            "file_path": "../../../../outside.tf",
            "file_line_range": [3, 4],
        }
    ]

    document = build_sarif(
        [make_finding(file_path="../../../../outside.tf")],
        unmapped=unmapped,
        scan_root=scan,
        repository_root=repo,
    )
    validator.validate(document)
    for result in document["runs"][0]["results"]:
        (location,) = result["locations"]
        assert location["physicalLocation"]["artifactLocation"] == {
            "uri": ".",
            "uriBaseId": "%SRCROOT%",
        }
        assert "region" not in location["physicalLocation"]
        assert result["properties"]["locationOutsideRepository"] is True
        assert "outside" not in json.dumps(result["partialFingerprints"])


def test_windows_separators_and_uri_delimiters_are_preserved_safely(validator):
    document = build_sarif(
        [make_finding(file_path=r"\src\my file#1?.tf")],
        scan_root=r"C:\checkout\examples\vulnerable-aws",
        repository_root=r"C:\checkout",
    )
    validator.validate(document)
    location = document["runs"][0]["results"][0]
    assert location["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "examples/vulnerable-aws/src/my%20file%231%3F.tf"
    )


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
            "tf-eu-guard",
            "scan",
            "--checkov-json",
            str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json"),
            "--output",
            "sarif",
        ],
    )
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


def test_cli_source_scan_uses_repository_relative_locations(
    monkeypatch, tmp_path, repo_root, capsys, validator
):
    """A source scan keeps Checkov's /file.tf paths anchored to the scan root."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tf-eu-guard",
            "scan",
            str(repo_root / "examples" / "vulnerable-aws"),
            "--checkov-json",
            str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json"),
            "--output",
            "sarif",
        ],
    )
    assert main() == 0
    document = json.loads(capsys.readouterr().out)
    validator.validate(document)
    repository_uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in document["runs"][0]["results"]
        if result["locations"]
    ]
    assert "examples/vulnerable-aws/iam.tf" in repository_uris
    assert all(".." not in uri and not uri.startswith("/") for uri in repository_uris)
    assert all((repo_root / unquote(uri)).is_file() for uri in repository_uris)


def test_cli_sarif_output_file(monkeypatch, tmp_path, repo_root, capsys, validator):
    out_file = tmp_path / "nested" / "results.sarif"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tf-eu-guard",
            "scan",
            "--checkov-json",
            str(repo_root / "tests/fixtures/checkov-vulnerable-tf.json"),
            "--output",
            "sarif",
            "--output-file",
            str(out_file),
        ],
    )
    assert main() == 0
    document = json.loads(out_file.read_text(encoding="utf-8"))
    validator.validate(document)
    assert "SARIF report written" in capsys.readouterr().out


# --- T-13: Code Scanning fields -------------------------------------------


@pytest.mark.parametrize(
    ("severity", "score"),
    [
        (Severity.CRITICAL, "9.5"),
        (Severity.HIGH, "8.0"),
        (Severity.MEDIUM, "5.5"),
        (Severity.LOW, "3.0"),
        (Severity.INFO, "0.0"),
    ],
)
def test_rule_security_severity_per_severity(validator, severity, score):
    document = build_sarif([make_finding(severity=severity)])
    validator.validate(document)
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    assert rule["properties"]["security-severity"] == score
    assert isinstance(rule["properties"]["security-severity"], str)


def test_rule_help_and_tags(validator):
    finding = make_finding(
        remediation="Set `encrypted = true` for *all* [buckets] <now>.",
        articles=[
            ArticleReference(Framework.NIS2, "Art. 21(2)(h)", "Cryptography"),
            ArticleReference(Framework.GDPR, "Art. 32(1)(a)", "Encryption"),
        ],
    )
    document = build_sarif([finding])
    validator.validate(document)
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    assert "Set `encrypted = true`" in rule["help"]["text"]
    assert "NIS2 Art. 21(2)(h)" in rule["help"]["text"]
    markdown = rule["help"]["markdown"]
    assert "\\`encrypted = true\\`" in markdown
    assert "\\*all\\*" in markdown and "\\[buckets\\]" in markdown
    assert "\\<now>" not in markdown and "\\<now\\>" in markdown
    assert "- NIS2 Art. 21(2)(h)" in markdown
    tags = rule["properties"]["tags"]
    assert tags[0] == "security"
    assert {"NIS2", "GDPR", "NIS2 Art. 21(2)(h)", "GDPR Art. 32(1)(a)"} <= set(tags)


def test_unmapped_rule_has_no_security_severity(validator):
    document = build_sarif(
        [],
        unmapped=[
            {
                "check_id": "CKV_X_1",
                "check_name": "x",
                "resource": "aws_x.y",
                "file_path": "a.tf",
                "file_line_range": [1, 2],
            }
        ],
    )
    validator.validate(document)
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    assert "security-severity" not in rule["properties"]
    assert "help" not in rule


def _fingerprints(document):
    return [r["partialFingerprints"]["tfEuGuard/v1"] for r in document["runs"][0]["results"]]


def test_fingerprints_are_stable_and_distinguish_resources(validator):
    findings = [
        make_finding(resource="aws_s3_bucket.a"),
        make_finding(resource="aws_s3_bucket.b"),
        make_finding(resource="aws_s3_bucket.a", file_path="other.tf"),
    ]
    first = build_sarif(findings)
    second = build_sarif(list(reversed(findings)))
    validator.validate(first)
    assert sorted(_fingerprints(first)) == sorted(_fingerprints(second))
    assert len(set(_fingerprints(first))) == 3
    assert all(len(fp) == 64 and int(fp, 16) >= 0 for fp in _fingerprints(first))
    # Line moves do not change the fingerprint.
    moved = build_sarif([make_finding(resource="aws_s3_bucket.a", file_line_range=[40, 50])])
    assert _fingerprints(moved)[0] == _fingerprints(build_sarif([findings[0]]))[0]


def test_outside_repo_fingerprints_differ_per_file(tmp_path):
    repo = tmp_path / "checkout"
    scan = repo / "src"
    scan.mkdir(parents=True)
    findings = [
        make_finding(file_path="../../one/x.tf"),
        make_finding(file_path="../../two/x.tf"),
    ]
    for kwargs in ({"scan_root": scan, "repository_root": repo}, {}):
        document = build_sarif(findings, **kwargs)
        if kwargs:
            assert len(set(_fingerprints(document))) == 2
    # No roots: in-repo-looking relative paths are normalized, so use absolute ones.
    document = build_sarif(
        [make_finding(file_path="/../a/x.tf"), make_finding(file_path="/../b/x.tf")],
        repository_root=repo,
    )
    assert len(set(_fingerprints(document))) == 2
    again = build_sarif(findings, scan_root=scan, repository_root=repo)
    assert _fingerprints(again) == _fingerprints(
        build_sarif(findings, scan_root=scan, repository_root=repo)
    )


def test_outside_path_key_without_scan_root_hashes_absolute_path(tmp_path):
    from tf_eu_guard.reporting.sarif_report import _outside_path_key

    repo = tmp_path / "checkout"
    repo.mkdir()
    key_a = _outside_path_key("/../a/x.tf", None, repo)
    key_b = _outside_path_key("/../b/x.tf", None, repo)
    assert re.fullmatch(r"outside:x\.tf:[0-9a-f]{16}", key_a)
    assert re.fullmatch(r"outside:x\.tf:[0-9a-f]{16}", key_b)
    assert key_a != key_b
    assert key_a == _outside_path_key("/../a/x.tf", None, repo)

    def build(*paths):
        return build_sarif([make_finding(file_path=p) for p in paths], repository_root=repo)

    first = _fingerprints(build("/../a/x.tf", "/../b/x.tf"))
    assert first[0] != first[1]
    assert first == _fingerprints(build("/../a/x.tf", "/../b/x.tf"))
