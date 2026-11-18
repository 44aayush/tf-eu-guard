"""--output markdown|csv, --summary-file, --counts-file (Task 11)."""

import csv
import io
import json
from pathlib import Path

from cli_helpers import FIXTURE, run_cli

from tf_eu_guard.cli.pipeline import ScanFindings
from tf_eu_guard.models import ArticleReference, EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting.csv_report import COLUMNS, render_csv
from tf_eu_guard.reporting.markdown_report import render_counts, render_markdown

FIXTURE_PATH = Path(__file__).parent.parent / FIXTURE


def _finding(resource="r", check_id="CKV_X_1", articles=2, severity=Severity.HIGH):
    arts = [
        ArticleReference(Framework.NIS2, "Art. 21", "Measures"),
        ArticleReference(Framework.GDPR, "Art. 32", "Security"),
    ][:articles]
    return EnrichedFinding(
        check_id=check_id,
        check_name="name",
        resource=resource,
        file_path="main.tf",
        file_line_range=[3, 9],
        guideline=None,
        articles=arts,
        severity=severity,
    )


def test_markdown_has_severity_table_and_findings():
    text = render_markdown(ScanFindings([_finding()], []), target="t", version="1.2.3")
    assert "tf-eu-guard 1.2.3" in text
    assert "| High | 1 |" in text
    assert "| HIGH | CKV_X_1 | r | main.tf:3 |" in text
    assert "Unmapped: 0 | Suppressed: 0 | Waived: 0 | Baselined: 0" in text


def test_markdown_escapes_pipes_and_html():
    result = ScanFindings([_finding("a|b`c<script>\nx")], [])
    text = render_markdown(result, target="t", version="1")
    assert "a\\|b\\`c&lt;script&gt; x" in text
    assert "<script>" not in text


def test_markdown_truncates():
    result = ScanFindings([_finding(f"r{i}") for i in range(60)], [])
    text = render_markdown(result, target="t", version="1", max_rows=50)
    assert "... and 10 more" in text


def test_markdown_lists_weakening_settings():
    result = ScanFindings([], [], weakening_settings=["baseline: x.json"])
    assert "baseline: x.json" in render_markdown(result, target="t", version="1")


def test_csv_one_row_per_article():
    rows = list(csv.reader(io.StringIO(render_csv(ScanFindings([_finding()], [])))))
    assert rows[0] == COLUMNS
    assert [r[8] for r in rows[1:]] == ["GDPR", "NIS2"]
    assert rows[1][0] == "active"


def test_csv_unmapped_and_suppressed_rows():
    check = {"check_id": "CKV_U", "resource": "u", "file_path": "f.tf", "file_line_range": [1, 2]}
    result = ScanFindings([], [check], suppressed_unmapped=[check])
    rows = list(csv.reader(io.StringIO(render_csv(result))))[1:]
    assert [r[0] for r in rows] == ["unmapped", "suppressed"]
    assert rows[0][1] == "" and rows[0][8] == ""


def test_csv_neutralises_formula_cells():
    for lead in ("=", "+", "-", "@", "\t", "\r"):
        text = render_csv(ScanFindings([_finding(f'{lead}HYPERLINK("x")')], []))
        assert f"'{lead}HYPERLINK" in text


def test_summary_file_written_alongside_json(monkeypatch, tmp_path, capsys):
    code = run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(FIXTURE_PATH),
        "--output",
        "json",
        "--summary-file",
        "out/s.md",
    )
    out = capsys.readouterr().out
    assert code in (0, 1)
    json.loads(out)  # stdout stays pure JSON
    assert "tf-eu-guard" in (tmp_path / "out" / "s.md").read_text(encoding="utf-8")


def test_counts_file_format(monkeypatch, tmp_path):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(FIXTURE_PATH),
        "--output",
        "dev",
        "--counts-file",
        "c.txt",
    )
    lines = (tmp_path / "c.txt").read_text(encoding="utf-8").splitlines()
    keys = [line.split("=")[0] for line in lines]
    assert keys == [
        "critical", "high", "medium", "low", "info",
        "unmapped", "suppressed", "waived", "baselined", "total",
    ]  # fmt: skip
    assert "high=" in lines[1] and int(lines[1].split("=")[1]) >= 1


def test_counts_file_follows_framework(monkeypatch, tmp_path, capsys):
    # CKV_AWS_273 is NIS2-only, CKV_AWS_53 GDPR-only, CKV_AWS_16 both (all HIGH).
    failed = [
        {
            "check_id": cid,
            "check_name": cid,
            "resource": f"aws_x.{cid}",
            "file_path": "/main.tf",
            "file_line_range": [1, 2],
            "guideline": None,
        }
        for cid in ("CKV_AWS_273", "CKV_AWS_53", "CKV_AWS_16")
    ]
    doc = {
        "check_type": "terraform",
        "summary": {"parsing_errors": 0},
        "results": {"passed_checks": [], "failed_checks": failed, "skipped_checks": []},
    }
    (tmp_path / "in.json").write_text(json.dumps(doc), encoding="utf-8")
    run_cli(
        monkeypatch, tmp_path, "--checkov-json", "in.json", "--framework", "nis2",
        "--output", "json", "--json-format", "object", "--counts-file", "c.txt",
    )  # fmt: skip
    findings = json.loads(capsys.readouterr().out)["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert {f["check_id"] for f in high} == {"CKV_AWS_273", "CKV_AWS_16"}
    counts = dict(
        line.split("=") for line in (tmp_path / "c.txt").read_text(encoding="utf-8").splitlines()
    )
    assert int(counts["high"]) == len(high) == 2


def test_render_counts_exact():
    text = render_counts(ScanFindings([_finding()], [{"check_id": "u"}]))
    assert text == (
        "critical=0\nhigh=1\nmedium=0\nlow=0\ninfo=0\n"
        "unmapped=1\nsuppressed=0\nwaived=0\nbaselined=0\ntotal=2\n"
    )


def test_output_csv_and_markdown_files(monkeypatch, tmp_path):
    for fmt, name in (("csv", "d/o.csv"), ("markdown", "d/o.md")):
        run_cli(
            monkeypatch, tmp_path, "--checkov-json", str(FIXTURE_PATH),
            "--output", fmt, "--output-file", name,
        )  # fmt: skip
    assert (tmp_path / "d/o.csv").read_text(encoding="utf-8").startswith("status,severity")
    assert "tf-eu-guard" in (tmp_path / "d/o.md").read_text(encoding="utf-8")


def test_output_csv_stdout(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, tmp_path, "--checkov-json", str(FIXTURE_PATH), "--output", "csv")
    assert capsys.readouterr().out.startswith("status,severity")


def test_csv_discloses_settings_on_stderr(monkeypatch, tmp_path, capsys):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(FIXTURE_PATH),
        "--output",
        "csv",
        "--exclude",
        "x",
    )
    captured = capsys.readouterr()
    assert "Scan settings that reduce findings:\n  exclude: x\n" in captured.err
    rows = list(csv.reader(io.StringIO(captured.out, newline="")))
    assert rows[0] == COLUMNS


def test_markdown_summary_discloses_settings(monkeypatch, tmp_path, capsys):
    run_cli(
        monkeypatch,
        tmp_path,
        "--checkov-json",
        str(FIXTURE_PATH),
        "--output",
        "markdown",
        "--exclude",
        "x",
    )
    assert "Settings that reduce findings" in capsys.readouterr().out
