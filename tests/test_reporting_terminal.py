"""Tests for the terminal (dev) report generator.

Exercises ``generate_dev_report`` with mock findings: rendering, severity
sorting, empty-findings handling, and the ``DevReporter`` class output.
"""

from io import StringIO

from rich.console import Console

from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting.dev_report import DevReporter, generate_dev_report


def _finding(severity=Severity.HIGH, **overrides):
    defaults = dict(
        check_id="CKV_AWS_18",
        check_name="Ensure the S3 bucket has access logging enabled",
        resource="aws_s3_bucket.data",
        file_path="/s3.tf",
        file_line_range=[1, 5],
        guideline=None,
        articles=[ArticleReference(Framework.GDPR, "Art. 32(1)(b)", "Confidentiality")],
        risk_explanation="Without access logging, unauthorized access is undetectable.",
        remediation='logging = { target_bucket = "log-bucket" }',
    )
    defaults.update(overrides)
    defaults["severity"] = severity
    return EnrichedFinding(**defaults)


def _capture(findings):
    """Run generate_dev_report with stdout captured; return printed text."""
    import contextlib

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    import tf_eu_guard.reporting.dev_report as mod
    original = mod.Console
    mod.Console = lambda: console
    try:
        with contextlib.redirect_stdout(StringIO()):
            generate_dev_report(findings)
    finally:
        mod.Console = original
    return buf.getvalue()


def test_empty_findings():
    out = _capture([])
    assert "No compliance findings" in out


def test_renders_finding_and_articles():
    out = _capture([_finding()])
    assert "CKV_AWS_18" in out
    assert "GDPR" in out
    assert "Art. 32(1)(b)" in out
    assert "aws_s3_bucket.data" in out
    assert "Remediation" in out


def test_severity_summary_counts():
    out = _capture([
        _finding(severity=Severity.CRITICAL),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.LOW),
    ])
    assert "Total Findings: 4" in out
    assert "CRITICAL: 1" in out
    assert "HIGH: 2" in out
    assert "LOW: 1" in out
    assert "MEDIUM" not in out  # absent severity not printed


def test_severity_sorting_within_file():
    # Insert LOW first; report must sort CRITICAL before it.
    out = _capture([
        _finding(severity=Severity.LOW),
        _finding(severity=Severity.CRITICAL, check_id="CKV_AWS_145"),
    ])
    crit_pos = out.index("CKV_AWS_145")
    low_pos = out.index("CKV_AWS_18")
    assert crit_pos < low_pos


def test_grouping_by_file():
    out = _capture([
        _finding(file_path="/a.tf"),
        _finding(file_path="/b.tf"),
    ])
    assert "/a.tf" in out and "/b.tf" in out


def test_dev_reporter_class_generates_text():
    from tf_eu_guard.models import ScanReport

    report = ScanReport(
        target_path="./terraform",
        scan_timestamp="2026-08-30",
        checkov_version="3.3.13",
        findings=[_finding()],
        total_checks_run=50,
        total_failed=1,
        total_passed=49,
    )
    reporter = DevReporter()
    text = reporter.generate(report)
    assert "tf-eu-guard scan results" in text
    assert "CKV_AWS_18" in text


def test_dev_reporter_writes_plain_text_file(tmp_path):
    from tf_eu_guard.models import ScanReport

    report = ScanReport(
        target_path="./terraform",
        scan_timestamp="2026-08-30",
        checkov_version="3.3.13",
        findings=[_finding()],
        total_checks_run=50,
        total_failed=1,
        total_passed=49,
    )
    out_path = tmp_path / "dev.txt"
    DevReporter().generate(report, output_path=out_path)
    content = out_path.read_text()
    assert "[bold]" not in content  # Rich markup stripped
    assert "CKV_AWS_18" in content
