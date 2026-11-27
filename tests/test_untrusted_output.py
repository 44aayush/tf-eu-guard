"""Untrusted strings from the scanned checkout must not forge or repaint terminal output."""

import contextlib
import datetime
from io import StringIO
from unittest.mock import patch

from rich.console import Console

import tf_eu_guard.reporting.dev_report as mod
from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting.dev_report import generate_dev_report
from tf_eu_guard.reporting.untrusted import sanitize
from tf_eu_guard.reporting.weakening import print_weakening_to_stderr
from tf_eu_guard.waivers import Waiver

EVIL_RESOURCE = "web\n::error title=X::forged\n\x1b]8;;https://evil\x1b\\"
EVIL_PATH = "/a\n::warning::b.tf"


def _finding(**overrides):
    defaults = dict(
        check_id="CKV_AWS_18",
        check_name="Ensure the S3 bucket has access logging enabled",
        resource="aws_s3_bucket.data",
        file_path="/s3.tf",
        file_line_range=[1, 5],
        guideline=None,
        severity=Severity.HIGH,
        articles=[ArticleReference(Framework.GDPR, "Art. 32(1)(b)", "Confidentiality")],
        risk_explanation="Risk.",
        remediation="fix = true",
    )
    defaults.update(overrides)
    return EnrichedFinding(**defaults)


def _render(**kwargs) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    with patch.object(mod, "Console", return_value=console):
        with contextlib.redirect_stdout(StringIO()):
            generate_dev_report(**kwargs)
    return buf.getvalue()


def _render_default_width(monkeypatch, **kwargs) -> str:
    """Render through the console dev_report builds itself, at the default 80 columns."""
    monkeypatch.delenv("COLUMNS", raising=False)
    buf = StringIO()
    real = Console

    def factory(**kw):
        return real(file=buf, force_terminal=False, **kw)

    with patch.object(mod, "Console", side_effect=factory):
        with contextlib.redirect_stdout(StringIO()):
            generate_dev_report(**kwargs)
    return buf.getvalue()


def _assert_neutral(out: str) -> None:
    assert not any(line.lstrip().startswith("::") for line in out.splitlines())
    assert "\x1b]8" not in out


def test_sanitize_escapes_controls():
    assert sanitize("a\nb\rc\x1b[2K\x07\x7f\x9b") == r"a\nb\rc\x1b[2K\x07\x7f\x9b"


def test_sanitize_escapes_bidi():
    assert sanitize("x\u202ey\u2066") == r"x\u202ey\u2066"


def test_sanitize_keeps_tabs_and_unicode_letters():
    assert sanitize("a\tcafé データ") == "a\tcafé データ"
    assert sanitize(None) == ""


def test_dev_report_neutralises_workflow_commands():
    finding = _finding(resource=EVIL_RESOURCE, file_path=EVIL_PATH)
    out = _render(findings=[finding])
    assert "forged" in out  # escaped, not dropped
    _assert_neutral(out)


def test_waiver_and_weakening_lines_are_sanitised(capsys):
    print_weakening_to_stderr(["exclude: a\n::error::x"])
    _assert_neutral(capsys.readouterr().err)

    waived = _finding()
    waived.waiver = Waiver(
        check_id="CKV_AWS_18",
        resource="aws_s3_bucket.data",
        reason="r",
        owner="o\n::error::x",
        expires=datetime.date(2099, 1, 1),
    )
    _assert_neutral(_render(findings=[], waived=[waived]))


WRAP_PAYLOAD = "accepted risk " + "b" * 50 + " ::error title=Forged::waiver"


def test_word_wrap_cannot_start_a_line_with_annotation_in_waiver_reason(monkeypatch):
    waived = _finding()
    waived.waiver = Waiver(
        check_id="CKV_AWS_18",
        resource="aws_s3_bucket.data",
        reason=WRAP_PAYLOAD,
        owner="o",
        expires=datetime.date(2099, 1, 1),
    )
    out = _render_default_width(monkeypatch, findings=[], waived=[waived])
    assert "::error title=Forged::waiver" in out
    _assert_neutral(out)


def test_word_wrap_cannot_start_a_line_with_annotation_in_suppression_reason(monkeypatch):
    suppressed = _finding(suppressed=True, suppression_reason=WRAP_PAYLOAD)
    out = _render_default_width(monkeypatch, findings=[], suppressed=[suppressed])
    assert "::error title=Forged::waiver" in out
    _assert_neutral(out)
