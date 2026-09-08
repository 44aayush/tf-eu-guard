"""Hermetic smoke tests for the HTML report generators (Phase 4).

These construct :class:`EnrichedFinding` objects directly, so they need neither
Checkov nor the registry — they exercise the ``dev`` (HTML), ``security`` and
``auditor`` reporters: document structure, that findings/articles are rendered,
file output, the empty-findings edge case, and HTML-escaping of untrusted fields.
"""

from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting.auditor_report import generate_auditor_report
from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report
from tf_eu_guard.reporting.security_report import generate_security_report


def _finding(
    check_id="CKV_AWS_20",
    severity=Severity.CRITICAL,
    articles=None,
    **overrides,
):
    """Build an EnrichedFinding with sensible defaults for report tests."""
    defaults = dict(
        check_name="Ensure the resource is not public",
        resource="aws_s3_bucket.data",
        file_path="/s3.tf",
        file_line_range=[6, 8],
        guideline="https://docs.example/CKV_AWS_20",
    )
    defaults.update(overrides)
    if articles is None:
        articles = [ArticleReference(Framework.GDPR, "Art. 32(1)(b)", "Confidentiality")]
    return EnrichedFinding(
        check_id=check_id,
        articles=articles,
        risk_explanation="Publicly readable data risks a confidentiality breach.",
        remediation='acl = "private"',
        severity=severity,
        **defaults,
    )


def _sample_findings():
    return [
        _finding(
            "CKV_AWS_20",
            Severity.CRITICAL,
            [
                ArticleReference(Framework.NIS2, "Art. 21(2)(i)", "Access control"),
                ArticleReference(Framework.GDPR, "Art. 32(1)(b)", "Confidentiality"),
            ],
        ),
        _finding(
            "CKV_AWS_16",
            Severity.HIGH,
            [
                ArticleReference(Framework.NIS2, "Art. 21(2)(h)", "Cryptography"),
                ArticleReference(Framework.GDPR, "Art. 32(1)(a)", "Encryption"),
            ],
            resource="aws_db_instance.app_db",
            file_path="/rds.tf",
            file_line_range=[1, 20],
        ),
        _finding(
            "EUGUARD_GDPR_001",
            Severity.HIGH,
            [ArticleReference(Framework.GDPR, "Art. 44", "Transfers to third countries")],
            resource="aws.non_eu",
            file_path="/main.tf",
        ),
    ]


def _is_html_document(doc: str) -> bool:
    return doc.lstrip().startswith("<!DOCTYPE html>") and "</html>" in doc


def _zero_line_findings():
    """One finding per non-Terraform ID format, all with a degenerate [0, 0] range.

    Mirrors what Checkov emits for terraform_plan JSON (whole plan is one line),
    and covers CloudFormation logical IDs / Kubernetes kind-names, whose
    ``resource`` values don't follow Terraform's address syntax.
    """
    return [
        _finding(
            "CKV_AWS_17",
            Severity.HIGH,
            [ArticleReference(Framework.NIS2, "Art. 21(2)(h)", "Cryptography")],
            resource="aws_db_instance.default",
            file_path="/plan.json",
            file_line_range=[0, 0],
        ),
        _finding(
            "CKV_AWS_157",
            Severity.HIGH,
            [ArticleReference(Framework.GDPR, "Art. 32(1)(c)", "Availability")],
            resource="MyDBInstance",
            file_path="/template.yaml",
            file_line_range=[0, 0],
        ),
        _finding(
            "CKV_K8S_17",
            Severity.MEDIUM,
            [ArticleReference(Framework.NIS2, "Art. 21(2)(i)", "Access control")],
            resource="Pod/app",
            file_path="/deployment.yaml",
            file_line_range=[0, 0],
        ),
    ]


class TestNonTerraformFormats:
    """Reports must degrade gracefully for plan-JSON / CFN / K8s findings."""

    @staticmethod
    def _no_zero_line_ref(doc: str) -> bool:
        # A rendered location is "file:lines" or bare "file" — never "file:0-0".
        return ":0-0" not in doc

    def test_security_report_omits_zero_lines(self):
        doc = generate_security_report(_zero_line_findings())
        assert self._no_zero_line_ref(doc)
        assert "plan.json" in doc and "template.yaml" in doc

    def test_auditor_report_omits_zero_lines(self):
        doc = generate_auditor_report(_zero_line_findings())
        assert self._no_zero_line_ref(doc)

    def test_dev_html_report_omits_zero_lines(self):
        doc = generate_dev_html_report(_zero_line_findings())
        assert self._no_zero_line_ref(doc)

    def test_dev_terminal_report_omits_zero_lines(self, capsys):
        from tf_eu_guard.reporting.dev_report import generate_dev_report

        generate_dev_report(_zero_line_findings())
        out = capsys.readouterr().out
        assert "Lines: 0-0" not in out
        assert "Resource: Pod/app" in out  # non-Terraform ID renders fine

    def test_non_terraform_resource_ids_render(self):
        for doc in (
            generate_security_report(_zero_line_findings()),
            generate_auditor_report(_zero_line_findings()),
            generate_dev_html_report(_zero_line_findings()),
        ):
            for resource in ("MyDBInstance", "Pod/app"):
                assert resource in doc


class TestSecurityReport:
    def test_returns_html_document(self):
        doc = generate_security_report(
            _sample_findings(),
            target="examples/vulnerable-aws",
            timestamp="2026-01-01 00:00 UTC",
            version="0.1.0",
        )
        assert _is_html_document(doc)

    def test_renders_findings_severities_and_articles(self):
        doc = generate_security_report(_sample_findings())
        for cid in ("CKV_AWS_20", "CKV_AWS_16", "EUGUARD_GDPR_001"):
            assert cid in doc
        assert "CRITICAL" in doc and "HIGH" in doc
        assert "Art. 32(1)(b)" in doc
        assert "NIS2" in doc and "GDPR" in doc

    def test_writes_file(self, tmp_path):
        out = tmp_path / "scan-report.html"
        returned = generate_security_report(_sample_findings(), output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == returned
        assert _is_html_document(out.read_text(encoding="utf-8"))

    def test_empty_findings_is_valid_page(self):
        doc = generate_security_report([])
        assert _is_html_document(doc)
        assert "No compliance findings" in doc

    def test_escapes_untrusted_fields(self):
        doc = generate_security_report(
            [_finding(resource="<script>alert(1)</script>")]
        )
        assert "<script>alert(1)</script>" not in doc
        assert "&lt;script&gt;" in doc

    def test_first_line_is_doctype(self):
        # The test runner asserts on `head -1`, so the DOCTYPE must be line 1.
        doc = generate_security_report(_sample_findings())
        assert doc.splitlines()[0] == "<!DOCTYPE html>"


class TestAuditorReport:
    def test_returns_html_document(self):
        doc = generate_auditor_report(
            _sample_findings(),
            target="examples/vulnerable-aws",
            timestamp="2026-01-01 00:00 UTC",
            version="0.1.0",
        )
        assert _is_html_document(doc)

    def test_groups_by_framework_and_article_with_titles(self):
        doc = generate_auditor_report(_sample_findings())
        assert "NIS2" in doc and "GDPR" in doc
        assert "Art. 21(2)(i)" in doc
        assert "Art. 44" in doc
        assert "Access control" in doc  # article title surfaces
        assert "Executive summary" in doc

    def test_toc_anchors_resolve(self):
        doc = generate_auditor_report(_sample_findings())
        # The TOC links to #nis2-art-21-2-i and a matching id must exist.
        assert 'href="#nis2-art-21-2-i"' in doc
        assert 'id="nis2-art-21-2-i"' in doc

    def test_footer_has_version_and_timestamp(self):
        doc = generate_auditor_report(
            _sample_findings(), version="0.1.0", timestamp="2026-01-01 00:00 UTC"
        )
        assert "0.1.0" in doc
        assert "2026-01-01 00:00 UTC" in doc

    def test_writes_file(self, tmp_path):
        out = tmp_path / "auditor-report.html"
        returned = generate_auditor_report(_sample_findings(), output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == returned

    def test_empty_findings_is_valid_page(self):
        doc = generate_auditor_report([])
        assert _is_html_document(doc)
        assert "No mapped findings" in doc

    def test_escapes_untrusted_fields(self):
        doc = generate_auditor_report(
            [
                _finding(
                    resource="<img src=x onerror=alert(1)>",
                    articles=[
                        ArticleReference(Framework.NIS2, "Art. 21(2)(i)", "Access control")
                    ],
                )
            ]
        )
        assert "<img src=x onerror=alert(1)>" not in doc
        assert "&lt;img" in doc

    def test_first_line_is_doctype(self):
        doc = generate_auditor_report(_sample_findings())
        assert doc.splitlines()[0] == "<!DOCTYPE html>"


class TestDevHtmlReport:
    def test_returns_html_document(self):
        doc = generate_dev_html_report(
            _sample_findings(),
            target="examples/vulnerable-aws",
            timestamp="2026-01-01 00:00 UTC",
            version="0.1.0",
        )
        assert _is_html_document(doc)

    def test_renders_findings_severities_and_articles(self):
        doc = generate_dev_html_report(_sample_findings())
        for cid in ("CKV_AWS_20", "CKV_AWS_16", "EUGUARD_GDPR_001"):
            assert cid in doc
        assert "CRITICAL" in doc and "HIGH" in doc
        assert "Art. 32(1)(b)" in doc

    def test_groups_by_file(self):
        # The dev view is organised by file; each sample file should head a group.
        doc = generate_dev_html_report(_sample_findings())
        for path in ("/s3.tf", "/rds.tf", "/main.tf"):
            assert f'class="file">{path}' in doc

    def test_writes_file(self, tmp_path):
        out = tmp_path / "dev-report.html"
        returned = generate_dev_html_report(_sample_findings(), output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == returned
        assert _is_html_document(out.read_text(encoding="utf-8"))

    def test_empty_findings_is_valid_page(self):
        doc = generate_dev_html_report([])
        assert _is_html_document(doc)
        assert "No compliance findings" in doc

    def test_escapes_untrusted_fields(self):
        doc = generate_dev_html_report(
            [_finding(resource="<script>alert(1)</script>")]
        )
        assert "<script>alert(1)</script>" not in doc
        assert "&lt;script&gt;" in doc

    def test_first_line_is_doctype(self):
        doc = generate_dev_html_report(_sample_findings())
        assert doc.splitlines()[0] == "<!DOCTYPE html>"


class TestUnmappedCount:
    """Unmapped Checkov findings must be surfaced as a count in every format —
    present-but-unmapped, never silently absent (see TASKS.md P0 #2)."""

    def test_security_report_shows_unmapped_count(self):
        doc = generate_security_report(_sample_findings(), unmapped_count=9)
        assert "Unmapped Checkov findings: 9" in doc
        assert '<div class="label">Unmapped</div>' in doc  # summary stat card
        assert "no current EU regulatory mapping" in doc

    def test_security_report_unmapped_only_is_not_clean(self):
        doc = generate_security_report([], unmapped_count=4)
        assert "No compliance findings" not in doc
        assert "4 unmapped" in doc
        assert "not a clean bill of health" in doc

    def test_security_report_zero_unmapped_mentions_none(self):
        doc = generate_security_report(_sample_findings())
        assert "Unmapped Checkov findings" not in doc

    def test_auditor_report_scopes_unmapped_findings(self):
        doc = generate_auditor_report(_sample_findings(), unmapped_count=9)
        assert "Scope &amp; limitations" in doc
        assert "9" in doc and "no current EU regulatory mapping" in doc

    def test_auditor_report_unmapped_only_is_not_clean(self):
        doc = generate_auditor_report([], unmapped_count=4)
        assert "No mapped findings" in doc
        assert "4 unmapped" in doc

    def test_dev_html_report_shows_unmapped_count(self):
        doc = generate_dev_html_report(_sample_findings(), unmapped_count=9)
        assert "Unmapped Checkov findings: 9" in doc
        assert "9</b> unmapped" in doc  # summary chip

    def test_dev_terminal_report_shows_unmapped_count(self, capsys):
        from tf_eu_guard.reporting.dev_report import generate_dev_report

        generate_dev_report(_sample_findings(), unmapped_count=9)
        out = capsys.readouterr().out
        assert "Unmapped Checkov findings: 9" in out
        assert "no current EU regulatory mapping" in out

    def test_dev_terminal_report_unmapped_only_is_not_clean(self, capsys):
        from tf_eu_guard.reporting.dev_report import generate_dev_report

        generate_dev_report([], unmapped_count=4)
        out = capsys.readouterr().out
        assert "No compliance findings" not in out
        assert "4 unmapped" in out


# --- Guideline URL scheme validation (TASKS.md P0 #3) --------------------------

def test_safe_guideline_unit_gate():
    """Only http/https URLs without markup-breaking characters pass; a
    scheme-validated gate, because HTML-escaping neutralizes markup
    characters, not URL schemes."""
    from tf_eu_guard.reporting._html_common import safe_guideline

    ok = [
        "https://docs.prismacloud.io/en/enterprise-edition/policy-reference",
        "http://example.com/CKV_AWS_18",
    ]
    rejected = [
        None,
        "",
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "vbscript:msgbox(1)",
        "//protocol-relative.example/x",   # no explicit scheme
        "/relative/path",                  # no scheme
        "file:///etc/passwd",
        "https://ok.example/a]b",          # bracket — Rich markup breakout
        "https://ok.example/a b",          # whitespace
    ]
    for url in ok:
        assert safe_guideline(url) == url, url
    for url in rejected:
        assert safe_guideline(url) is None, url


def test_html_reports_render_no_link_for_javascript_guideline():
    """A javascript: guideline must not become a clickable link in any HTML
    report — the finding card should omit the Documentation link entirely."""
    findings = [_finding(guideline="javascript:alert(document.domain)")]
    for doc in (
        generate_security_report(findings),
        generate_auditor_report(findings),
        generate_dev_html_report(findings),
    ):
        assert 'class="doc"' not in doc, "doc link rendered for unsafe scheme"
        assert "javascript:" not in doc


def test_html_reports_render_no_link_for_other_unsafe_schemes():
    findings = [_finding(guideline="data:text/html;base64,PHNjcmlwdD4=")]
    for doc in (
        generate_security_report(findings),
        generate_auditor_report(findings),
        generate_dev_html_report(findings),
    ):
        assert 'class="doc"' not in doc
        assert "data:text/html" not in doc


def test_html_reports_still_link_safe_guidelines():
    """The gate must not over-reach: a normal https Checkov guideline still
    renders as a working link. (The auditor report renders findings in its
    own article-organized layout and never emits guideline links — for it,
    safe and unsafe schemes are equally link-free.)"""
    url = "https://docs.prismacloud.io/en/policy-reference/r/policy-aws"
    findings = [_finding(guideline=url)]
    for doc in (
        generate_security_report(findings),
        generate_dev_html_report(findings),
    ):
        assert f'href="{url}"' in doc
        assert 'class="doc"' in doc
    # Auditor renders internal #anchors but never external guideline links.
    auditor = generate_auditor_report(findings)
    assert 'href="http' not in auditor and 'href="https' not in auditor


def test_terminal_report_renders_no_link_for_javascript_guideline():
    """The Rich [link=...] path is scheme-gated too — Rich interpolates the
    value raw, so a javascript: guideline must not render a link there."""
    import sys
    from io import StringIO

    from tf_eu_guard.reporting.dev_report import generate_dev_report

    buf = StringIO()
    real_stdout = sys.stdout
    sys.stdout = buf
    try:
        generate_dev_report([_finding(guideline="javascript:alert(1)")])
    finally:
        sys.stdout = real_stdout
    out = buf.getvalue()
    assert "javascript:" not in out
    assert "Documentation" not in out  # link line omitted entirely


def test_terminal_report_still_links_safe_guidelines():
    """Rich only emits hyperlink escapes on a link-capable terminal; on plain
    streams the visible anchor text is what proves the link line rendered."""
    import sys
    from io import StringIO

    from tf_eu_guard.reporting.dev_report import generate_dev_report

    buf = StringIO()
    real_stdout = sys.stdout
    sys.stdout = buf
    try:
        generate_dev_report([_finding(guideline="https://docs.example/CKV_AWS_18")])
    finally:
        sys.stdout = real_stdout
    out = buf.getvalue()
    assert "→ Documentation" in out  # link line rendered
