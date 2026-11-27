"""Report-format dispatch for the command-line interface."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from tf_eu_guard import __version__
from tf_eu_guard.cli.paths import find_repository_root, sarif_scan_root
from tf_eu_guard.json_layout import resolve_json_format
from tf_eu_guard.mapping.coverage import RequirementResult
from tf_eu_guard.mapping.loader import LoadedRegistry
from tf_eu_guard.models import EnrichedFinding
from tf_eu_guard.reporting.auditor_report import generate_auditor_report
from tf_eu_guard.reporting.csv_report import render_csv
from tf_eu_guard.reporting.dev_html_report import generate_dev_html_report
from tf_eu_guard.reporting.dev_report import generate_dev_report
from tf_eu_guard.reporting.markdown_report import render_counts, render_markdown
from tf_eu_guard.reporting.sarif_report import build_sarif
from tf_eu_guard.reporting.security_report import generate_security_report
from tf_eu_guard.reporting.sorting import (
    sort_findings,
    sort_unmapped_findings,
    sorted_articles,
)
from tf_eu_guard.reporting.weakening import print_weakening_to_stderr

if TYPE_CHECKING:
    from tf_eu_guard.cli.pipeline import ScanFindings

JSON_SCHEMA_VERSION = "3"
_IMPLICIT_JSON_FORMAT_WARNING = (
    "Warning: --json-format not given; using the deprecated 'array' layout. "
    "Pass --json-format object (recommended) or --json-format array to silence "
    "this warning; the default changes to 'object' in a future release."
)
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _json_array(
    findings: list[EnrichedFinding],
    suppressed: list[EnrichedFinding] | None,
    waived: list[EnrichedFinding] | None = None,
    baselined: list[EnrichedFinding] | None = None,
) -> list[dict[str, Any]]:
    """Legacy array format: five core keys plus the suppression fields."""
    known = {id(f) for f in baselined or []}
    return [
        {
            "check_id": finding.check_id,
            "suppressed": finding.suppressed,
            "suppression_reason": finding.suppression_reason,
            "waived": finding.waiver is not None,
            "baselined": id(finding) in known,
            "severity": finding.severity.value,
            "resource": finding.resource,
            "file_path": finding.file_path,
            "articles": [
                {"framework": article.framework.value, "article": article.article}
                for article in sorted_articles(finding)
            ],
        }
        for finding in sort_findings(
            [*findings, *(suppressed or []), *(waived or []), *(baselined or [])]
        )
    ]


def _finding_entry(finding: EnrichedFinding) -> dict[str, Any]:
    return {
        "check_id": finding.check_id,
        "check_name": finding.check_name,
        "resource": finding.resource,
        "file_path": finding.file_path,
        "file_line_range": list(finding.file_line_range),
        "severity": finding.severity.value,
        "articles": [
            {
                "framework": article.framework.value,
                "article": article.article,
                "title": article.title,
            }
            for article in sorted_articles(finding)
        ],
        "risk_explanation": finding.risk_explanation,
        "remediation": finding.remediation,
        "guideline": finding.guideline,
        "suppressed": finding.suppressed,
        "suppression_reason": finding.suppression_reason,
    }


def build_json_object(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    checkov_version: str | None = None,
    requirements: list[RequirementResult] | None = None,
    registry: LoadedRegistry | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the versioned object format (schema: ``tf_eu_guard/schemas/report.schema.json``).

    ``summary.by_severity`` counts active (unsuppressed) mapped findings.
    ``summary.unmapped`` and ``summary.suppressed`` count entries of the
    ``unmapped`` list and the suppressed entries across both lists;
    ``summary.total`` is ``len(findings) + len(unmapped)``.
    """
    mapped = sort_findings([*findings, *(suppressed or [])])
    raw_unmapped = sort_unmapped_findings([*unmapped, *(suppressed_unmapped or [])])
    by_severity = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        by_severity[finding.severity.value] += 1

    finding_entries = [_finding_entry(finding) for finding in mapped]
    unmapped_entries = [
        {
            "check_id": check.get("check_id"),
            "check_name": check.get("check_name"),
            "resource": check.get("resource"),
            "file_path": check.get("file_path"),
            "file_line_range": list(check.get("file_line_range") or [0, 0]),
            "suppressed": bool(check.get("suppressed", False)),
        }
        for check in raw_unmapped
    ]
    suppressed_total = sum(
        1 for entry in [*finding_entries, *unmapped_entries] if entry["suppressed"]
    )
    document: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": {"name": "tf-eu-guard", "version": __version__},
        "checkov_version": checkov_version,
        "scan": {
            "target": str(args.path) if args.path else f"checkov-json:{args.checkov_json}",
            "iac_type": args.iac_type,
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "weakening_settings": list(weakening_settings or []),
        },
        "summary": {
            "by_severity": by_severity,
            "unmapped": len(unmapped_entries),
            "suppressed": suppressed_total,
            "total": len(findings) + len(unmapped),
        },
        "findings": finding_entries,
        "unmapped": unmapped_entries,
        "requirements": [
            {
                "framework": row.requirement.framework.value,
                "article": row.requirement.article,
                "title": row.requirement.title,
                "category": row.requirement.category.value,
                "mapped_checks": row.requirement.check_count,
                "ran": row.ran,
                "passed": row.passed,
                "failed": row.failed,
                "suppressed": row.suppressed,
                "waived": row.waived,
            }
            for row in requirements or []
        ],
        "registry": {
            "overlays": [str(path) for path in registry.overlay_files] if registry else [],
            "overridden": list(registry.overridden) if registry else [],
        },
        "baselined": [_finding_entry(finding) for finding in sort_findings(baselined or [])],
        "waived": [
            {
                **_finding_entry(finding),
                "waiver": {
                    "owner": finding.waiver.owner,
                    "reason": finding.waiver.reason,
                    "expires": finding.waiver.expires.isoformat(),
                    "file": finding.waiver.file,
                },
            }
            for finding in sort_findings(waived or [])
            if finding.waiver
        ],
    }
    if provenance is not None:
        document["provenance"] = provenance
    return document


def render_json_report(
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    args: argparse.Namespace | None = None,
    checkov_version: str | None = None,
    requirements: list[RequirementResult] | None = None,
    registry: LoadedRegistry | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    provenance: dict[str, Any] | None = None,
) -> None:
    """Print the JSON report, or write it to ``--output-file`` (UTF-8)."""
    output_file = getattr(args, "output_file", None)
    if args is not None and getattr(args, "json_format", None) is None:
        print(_IMPLICIT_JSON_FORMAT_WARNING, file=sys.stderr)
    if args is not None and resolve_json_format(args) == "object":
        document: Any = build_json_object(
            args,
            findings,
            unmapped,
            suppressed,
            suppressed_unmapped,
            checkov_version,
            requirements,
            registry,
            waived,
            weakening_settings,
            baselined,
            provenance,
        )
    else:
        document = _json_array(findings, suppressed, waived, baselined)
        # The bare array has no room for metadata; stdout must stay pure.
        print_weakening_to_stderr(weakening_settings or [])
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(text + "\n", encoding="utf-8")
        print(
            f"JSON report written to {output_file} "
            f"({len(findings)} mapped, {len(unmapped)} unmapped findings; "
            f"{len(suppressed or []) + len(suppressed_unmapped or [])} suppressed)."
        )
        return
    print(text)
    if args is not None and resolve_json_format(args) == "object":
        return  # the object carries unmapped findings itself
    # Machine-readable stdout stays a pure findings array; the unmapped count
    # goes to stderr so pipelines parsing stdout are unaffected while humans
    # still see it.
    if unmapped:
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) not shown above "
            f"(no current EU regulatory mapping).",
            file=sys.stderr,
        )
    if suppressed_unmapped:
        print(
            f"Note: {len(suppressed_unmapped)} unmapped Checkov finding(s) suppressed by "
            f"inline comments not shown above (no current EU regulatory mapping).",
            file=sys.stderr,
        )


def sarif_document(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
) -> dict[str, Any]:
    """Build the SARIF document for a scan."""
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"
    scan_root = sarif_scan_root(args.path, args.iac_type)
    return build_sarif(
        findings,
        unmapped=unmapped,
        version=__version__,
        target=target,
        scan_root=scan_root,
        repository_root=find_repository_root(scan_root),
        suppressed=suppressed,
        suppressed_unmapped=suppressed_unmapped,
        waived=waived,
        weakening_settings=weakening_settings,
        baselined=baselined,
    )


def render_sarif_report(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
) -> None:
    """Render SARIF to stdout or the requested output file."""
    document = sarif_document(
        args,
        findings,
        unmapped,
        suppressed,
        suppressed_unmapped,
        waived,
        weakening_settings,
        baselined,
    )
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"SARIF report written to {args.output_file} "
            f"({len(findings)} mapped, {len(unmapped)} unmapped findings; "
            f"{len(suppressed or []) + len(suppressed_unmapped or [])} suppressed)."
        )
        return

    print(json.dumps(document, indent=2, sort_keys=True))
    # Same stdout-purity policy as --output json: the unmapped note goes to
    # stderr.
    if unmapped:
        print(
            f"Note: {len(unmapped)} unmapped Checkov finding(s) included "
            f"as note-level results with mapped=false.",
            file=sys.stderr,
        )


def render_html_reports(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    requirements: list[RequirementResult] | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    provenance: dict[str, Any] | None = None,
) -> None:
    """Render one or all HTML report formats."""
    now = datetime.now(UTC)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    # Microseconds sort chronologically; the random suffix prevents concurrent
    # scans in the same clock tick from sharing a name.
    timestamp_suffix = f"{now:%Y%m%dT%H%M%S%fZ}_{uuid4().hex}"
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"

    # Default to reports/ directory. Unique names prevent scans running
    # concurrently from overwriting one another.
    # The directory is created only when a default path is actually used, so
    # an explicit --output-file leaves no empty reports/ behind.
    output_directory = args.output_dir or Path("reports")

    report_generators = {
        "dev": (f"dev_report_{timestamp_suffix}.html", generate_dev_html_report),
        "security": (f"scan_report_{timestamp_suffix}.html", generate_security_report),
        "auditor": (f"auditor_report_{timestamp_suffix}.html", generate_auditor_report),
    }
    report_kinds = ["dev", "security", "auditor"] if args.output == "all" else [args.output]

    written_paths = []
    for report_kind in report_kinds:
        default_name, generator = report_generators[report_kind]
        # --output-file only overrides the destination for a single format.
        if args.output == "all" or not args.output_file:
            output_path = output_directory / default_name
        else:
            output_path = args.output_file
        # Keep --output-file behavior consistent across report formats: custom
        # HTML destinations may point into a directory that does not exist yet.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        extra = (
            {"requirements": requirements, "provenance": provenance}
            if report_kind == "auditor"
            else {}
        )
        generator(
            findings,
            target=target,
            timestamp=timestamp,
            version=__version__,
            output_path=output_path,
            unmapped_count=len(unmapped),
            unmapped=unmapped if getattr(args, "show_unmapped", False) else None,
            suppressed=suppressed,
            suppressed_unmapped=suppressed_unmapped,
            waived=waived,
            weakening_settings=weakening_settings,
            baselined=baselined,
            **extra,
        )
        written_paths.append(output_path)

    label = "Reports" if len(written_paths) > 1 else f"{args.output.capitalize()} report"
    suppressed_total = len(suppressed or []) + len(suppressed_unmapped or [])
    suppressed_note = f", {suppressed_total} suppressed" if suppressed_total else ""
    print(f"{label} written ({len(findings)} findings{suppressed_note}):")
    for output_path in written_paths:
        print(f"  {output_path}")


def render_markdown_csv_outputs(args: argparse.Namespace, result: "ScanFindings") -> None:
    """Handle ``--output markdown|csv`` plus ``--summary-file`` / ``--counts-file``."""
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"

    def write(path: Path, text: str, newline: str | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline=newline) as handle:
            handle.write(text)

    summary = render_markdown(result, target=target, version=__version__)
    if args.summary_file:
        write(args.summary_file, summary)
    if args.counts_file:
        write(args.counts_file, render_counts(result))
    if args.output in ("markdown", "csv"):
        text = summary if args.output == "markdown" else render_csv(result)
        if args.output_file:
            write(args.output_file, text, newline="" if args.output == "csv" else None)
            print(f"{args.output.capitalize()} report written to {args.output_file}.")
        else:
            sys.stdout.write(text)
        if args.output == "csv":  # CSV has no room for metadata; markdown carries its own section
            print_weakening_to_stderr(result.weakening_settings)


def render_scan_output(
    args: argparse.Namespace,
    findings: list[EnrichedFinding],
    unmapped: list[dict[str, Any]],
    suppressed: list[EnrichedFinding] | None = None,
    suppressed_unmapped: list[dict[str, Any]] | None = None,
    checkov_version: str | None = None,
    requirements: list[RequirementResult] | None = None,
    registry: LoadedRegistry | None = None,
    waived: list[EnrichedFinding] | None = None,
    weakening_settings: list[str] | None = None,
    baselined: list[EnrichedFinding] | None = None,
    provenance: dict[str, Any] | None = None,
) -> None:
    """Dispatch a scan result to the selected report format."""
    if args.output == "dev":
        generate_dev_report(
            findings,
            unmapped_count=len(unmapped),
            suppressed=suppressed,
            suppressed_unmapped=suppressed_unmapped,
            unmapped=unmapped if getattr(args, "show_unmapped", False) else None,
            waived=waived,
            weakening_settings=weakening_settings,
            baselined=baselined,
        )
    elif args.output == "json":
        render_json_report(
            findings,
            unmapped,
            suppressed,
            suppressed_unmapped,
            args,
            checkov_version,
            requirements,
            registry,
            waived,
            weakening_settings,
            baselined,
            provenance,
        )
    elif args.output == "sarif":
        render_sarif_report(
            args,
            findings,
            unmapped,
            suppressed,
            suppressed_unmapped,
            waived,
            weakening_settings,
            baselined,
        )
    elif args.output in ("security", "auditor", "all"):
        render_html_reports(
            args,
            findings,
            unmapped,
            suppressed,
            suppressed_unmapped,
            requirements,
            waived,
            weakening_settings,
            baselined,
            provenance,
        )


def check_evidence_dir(directory: Path) -> None:
    """Refuse an existing file or non-empty directory (``ValueError``: exit 2)."""
    if directory.is_file() or (directory.is_dir() and any(directory.iterdir())):
        raise ValueError(f"--evidence-dir {directory} must not exist or must be an empty directory")


def write_evidence_bundle(
    args: argparse.Namespace,
    result: "ScanFindings",
    requirements: list[RequirementResult] | None,
    provenance: dict[str, Any],
) -> None:
    """Write the reports plus ``manifest.json`` (SHA-256 of every file) to ``--evidence-dir``."""
    directory: Path = args.evidence_dir
    check_evidence_dir(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"
    common: dict[str, Any] = {
        "target": target,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": __version__,
        "unmapped_count": len(result.unmapped),
        "unmapped": result.unmapped if getattr(args, "show_unmapped", False) else None,
        "suppressed": result.suppressed,
        "suppressed_unmapped": result.suppressed_unmapped,
        "waived": result.waived,
        "weakening_settings": result.weakening_settings,
        "baselined": result.baselined if args.baseline else None,
    }
    generate_dev_html_report(result.findings, output_path=directory / "dev.html", **common)
    generate_security_report(result.findings, output_path=directory / "security.html", **common)
    generate_auditor_report(
        result.findings,
        output_path=directory / "auditor.html",
        requirements=requirements,
        provenance=provenance,
        **common,
    )
    report = build_json_object(
        args,
        result.findings,
        result.unmapped,
        result.suppressed,
        result.suppressed_unmapped,
        result.checkov_version,
        requirements,
        result.registry,
        result.waived,
        result.weakening_settings,
        result.baselined if args.baseline else None,
        provenance,
    )
    (directory / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    sarif = sarif_document(
        args,
        result.findings,
        result.unmapped,
        result.suppressed,
        result.suppressed_unmapped,
        result.waived,
        result.weakening_settings,
        result.baselined if args.baseline else None,
    )
    (directory / "report.sarif").write_text(
        json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / "summary.md").write_text(
        render_markdown(result, target=target, version=__version__), encoding="utf-8"
    )
    files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
    }
    manifest = {
        "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provenance": provenance,
        "files": files,
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"Evidence bundle written to {directory} ({len(files)} files + manifest.json).",
        file=sys.stderr,
    )
