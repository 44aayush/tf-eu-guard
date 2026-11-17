"""Report polish: severity palettes, badge contrast, CSP, unmapped footer, output dirs."""

import re

import pytest

from tests.cli_helpers import FIXTURE, run_cli
from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting import styles
from tf_eu_guard.reporting.auditor_report import generate_auditor_report
from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report
from tf_eu_guard.reporting.sarif_report import SECURITY_SEVERITY, sarif_level
from tf_eu_guard.reporting.security_report import generate_security_report

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
HTML_GENERATORS = [generate_security_report, generate_auditor_report, generate_dev_html_report]


def _finding(severity=Severity.HIGH):
    return EnrichedFinding(
        check_id="CKV_AWS_18",
        check_name="name",
        resource="aws_s3_bucket.a",
        file_path="/a.tf",
        file_line_range=[1, 2],
        guideline=None,
        articles=[ArticleReference(Framework.GDPR, "Art. 32(1)(b)", "Confidentiality")],
        severity=severity,
        risk_explanation="risk",
    )


def _luminance(color: str) -> float:
    channels = [int(color.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(foreground: str, background: str) -> float:
    light, dark = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


@pytest.mark.parametrize("severity", list(Severity))
def test_every_severity_has_an_entry_in_every_map(severity):
    for mapping in (
        styles.SEVERITY_COLOR,
        styles.SEVERITY_COLOR_TERMINAL,
        styles.BADGE_TEXT_COLOR,
        SECURITY_SEVERITY,
    ):
        assert severity in mapping
    assert severity in styles.SEVERITY_ORDER
    assert sarif_level(severity)


@pytest.mark.parametrize("severity", list(Severity))
def test_badge_text_reaches_wcag_aa_contrast(severity):
    ratio = contrast(styles.BADGE_TEXT_COLOR[severity], styles.SEVERITY_COLOR[severity])
    assert ratio >= 4.5, f"{severity.value}: {ratio:.2f}"


@pytest.mark.parametrize("severity", list(Severity))
def test_rendered_badge_uses_computed_text_color(severity):
    html = generate_security_report([_finding(severity)])
    expected = (
        f'style="background:{styles.SEVERITY_COLOR[severity]};'
        f'color:{styles.BADGE_TEXT_COLOR[severity]}"'
    )
    assert expected in html
    html = generate_auditor_report([_finding(severity)])
    assert expected in html


@pytest.mark.parametrize("generator", HTML_GENERATORS)
def test_html_reports_carry_csp_and_reference_nothing_external(generator):
    html = generator([_finding()], unmapped_count=1)
    assert f'<meta http-equiv="Content-Security-Policy" content="{CSP}">' in html
    assert "<script" not in html.lower()
    assert "<svg" not in html.lower()
    # No resource loads: the only URLs are user-facing documentation hrefs.
    assert not re.search(r"\b(src|srcset)\s*=", html)
    assert "<link" not in html.lower()
    assert "@import" not in html and "url(" not in html


@pytest.mark.parametrize("generator", [generate_security_report, generate_dev_html_report])
def test_footer_omits_unmapped_sentence_at_zero(generator):
    assert "unmapped Checkov finding(s)" not in generator([_finding()], unmapped_count=0)
    assert "3 unmapped Checkov finding(s) were reported separately" in generator(
        [_finding()], unmapped_count=3
    )


def test_explicit_output_file_leaves_no_default_reports_dir(monkeypatch, tmp_path, repo_root):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "out" / "sec.html"
    rc = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "security",
        "--output-file",
        str(target),
    )
    assert rc in (0, 1)
    assert target.is_file()
    assert not (tmp_path / "reports").exists()


def test_default_output_still_creates_reports_dir(monkeypatch, tmp_path, repo_root):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(repo_root / FIXTURE),
        "--output",
        "security",
    )
    assert list((tmp_path / "reports").glob("scan_report_*.html"))


def test_default_registry_path_is_the_packaged_mapping_directory():
    from tf_eu_guard.cli import _default_registry_path

    path = _default_registry_path()
    assert path.name == "mapping" and path.parent.name == "tf_eu_guard"
    assert list(path.glob("registry-*.yaml"))


def test_severity_bar_rules_are_block_level_so_bars_cannot_collapse():
    css = styles.SECURITY_CSS
    for selector in (".chart .track", ".chart .bar"):
        rule = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
        assert rule is not None, selector
        assert re.search(r"display:\s*block", rule.group(1)), selector
