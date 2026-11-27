"""Scan acquisition and framework filtering for the CLI."""

import argparse
import sys
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import tf_eu_guard.checkov_runner as checkov_runner
from tf_eu_guard.baseline import finding_key, load_baseline
from tf_eu_guard.changed import changed_files, in_changed_scope
from tf_eu_guard.checkov.json import allow_partial_results, checkov_version_of
from tf_eu_guard.cli.paths import sarif_scan_root, scope_risk_text
from tf_eu_guard.constants import DEFAULT_CHECKOV_TIMEOUT
from tf_eu_guard.mapping.coverage import RequirementResult
from tf_eu_guard.mapping.loader import (
    LoadedRegistry,
    load_registry_with_overlays,
    split_findings,
)
from tf_eu_guard.models import EnrichedFinding, Framework, Severity
from tf_eu_guard.reporting.untrusted import sanitize
from tf_eu_guard.residency import (
    DEFAULT_POLICY,
    aws_region_unset_warning,
    gcp_region_unset_warning,
    residency_env,
)
from tf_eu_guard.waivers import WAIVER_FILENAME, apply_waivers, load_waivers


@dataclass
class ScanFindings:
    """Findings of one scan, split by registry coverage and suppression."""

    findings: list[EnrichedFinding]
    unmapped: list[dict[str, Any]]
    suppressed: list[EnrichedFinding] = field(default_factory=list)
    suppressed_unmapped: list[dict[str, Any]] = field(default_factory=list)
    checkov_version: str | None = None
    registry: LoadedRegistry | None = None
    passed: list[EnrichedFinding] = field(default_factory=list)
    waived: list[EnrichedFinding] = field(default_factory=list)
    # Human-readable settings that reduce findings; every report prints them.
    weakening_settings: list[str] = field(default_factory=list)
    # Active mapped findings already present in the --baseline file.
    baselined: list[EnrichedFinding] = field(default_factory=list)
    # Active unmapped findings already present in the --baseline file.
    baselined_unmapped: list[dict[str, Any]] = field(default_factory=list)
    # Checkov's `summary` dict (counts, resource_count) for the provenance block.
    checkov_summary: dict[str, Any] = field(default_factory=dict)
    # (active + baselined, suppressed, waived) before --changed-since filtering; the
    # requirement matrix must not change with that flag. None means no filtering.
    matrix_inputs: (
        tuple[list[EnrichedFinding], list[EnrichedFinding], list[EnrichedFinding]] | None
    ) = None
    # Filled by run_scan (public API ``ScanResult``): matrix rows and provenance block.
    requirements: list[RequirementResult] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    # What run_scan's stderr count lines need; printed after --framework filtering.
    waiver_path: Path | None = None
    baseline_origin: str = ""  # e.g. "from 2026-01-01 (5 days old)"; "" without --baseline


def _today() -> date:
    """Today's date; a seam so tests can pin waiver expiry."""
    return date.today()


def _waiver_path(args: argparse.Namespace) -> Path | None:
    """``--waivers`` if given, else the waiver file in a source scan's root, if present.

    An explicit ``--config`` disables discovery: a trusted config must not be undercut by
    a waiver file shipped inside the scanned code.
    """
    explicit = getattr(args, "waivers", None)
    if explicit:
        return Path(explicit)
    if getattr(args, "config", None):
        return None
    if args.checkov_json or not args.path:
        return None
    root = args.path if args.path.is_dir() else args.path.parent
    candidate = root / WAIVER_FILENAME
    if not candidate.is_file():
        return None
    if getattr(args, "no_discovery", False):
        print(f"Note: --no-discovery: ignored {sanitize(candidate)}", file=sys.stderr)
        return None
    return candidate


def _apply_waiver_file(
    path: Path,
    active: list[EnrichedFinding],
    suppressed: list[EnrichedFinding],
    max_days: int | None = None,
) -> tuple[list[EnrichedFinding], list[EnrichedFinding], list[EnrichedFinding], int]:
    """Return ``(active, suppressed, waived, entry count)``; warnings go to stderr."""
    waivers = load_waivers(path)
    for w in waivers:
        if w.file is None:
            print(
                f"Warning: waiver for {sanitize(w.check_id)} {sanitize(w.resource)} has no file "
                "pattern; it matches that resource in every file",
                file=sys.stderr,
            )
    result = apply_waivers([*active, *suppressed], waivers, _today(), max_days)
    for w in result.too_long:
        print(
            f"Warning: waiver for {sanitize(w.check_id)} {sanitize(w.resource)} expires "
            f"{w.expires.isoformat()}, more than {max_days} days ahead (--max-waiver-days); "
            "not applied",
            file=sys.stderr,
        )
    for w in result.expired:
        print(
            f"Waiver expired on {w.expires.isoformat()}: "
            f"{sanitize(w.check_id)} {sanitize(w.resource)} (owner {sanitize(w.owner)})",
            file=sys.stderr,
        )
    if result.unused:
        listed = ", ".join(f"{sanitize(w.check_id)} {sanitize(w.resource)}" for w in result.unused)
        print(f"Warning: waiver(s) in {sanitize(path)} matched nothing: {listed}", file=sys.stderr)
    return (
        [f for f in result.active if not f.suppressed],
        [f for f in result.active if f.suppressed],
        result.waived,
        len(waivers),
    )


def _apply_severity_overrides(
    overrides: dict[str, str],
    loaded: LoadedRegistry,
    groups: list[list[EnrichedFinding]],
) -> tuple[list[list[EnrichedFinding]], list[str]]:
    """Re-grade mapped findings; returns the groups and one disclosure line per override."""
    lines: list[str] = []
    for check_id, level in overrides.items():
        mapping = loaded.mappings.get(check_id)
        if mapping is None:
            print(
                f"Warning: severity override for {sanitize(check_id)} ignored: not in the registry",
                file=sys.stderr,
            )
            continue
        lines.append(f"severity override: {check_id} {mapping.severity.value}→{level}")
    known = {c: Severity(v) for c, v in overrides.items() if c in loaded.mappings}
    return [
        [replace(f, severity=known[f.check_id]) if f.check_id in known else f for f in group]
        for group in groups
    ], lines


def load_scan_findings(
    args: argparse.Namespace,
    registry_path: Path | None,
) -> ScanFindings:
    """Run or load Checkov, then split findings by registry coverage.

    Active findings come from ``failed_checks``; findings suppressed by inline
    ``checkov:skip`` comments come from ``skipped_checks`` and stay separate.
    """
    if getattr(args, "changed_since", None) and (
        args.checkov_json or args.iac_type == "terraform_plan"
    ):
        raise ValueError(
            "--changed-since cannot be used with --checkov-json or --iac-type terraform_plan: "
            "finding paths cannot be matched to a checkout"
        )
    if getattr(args, "var_files", None) or getattr(args, "download_external_modules", False):
        if args.checkov_json or args.iac_type != "terraform":
            raise ValueError(
                "--var-file and --download-external-modules are only valid with "
                "--iac-type terraform and a live scan (not --checkov-json)"
            )
    policy = getattr(args, "residency_policy", DEFAULT_POLICY)
    allowed = getattr(args, "allowed_regions", None)
    if args.checkov_json:
        if policy != DEFAULT_POLICY or allowed:
            print(
                "Warning: --residency-policy/--allowed-regions are ignored with "
                "--checkov-json; the results were computed with the policy in "
                "effect when Checkov ran.",
                file=sys.stderr,
            )
    extra_types = ("secrets",) if getattr(args, "secrets", False) else ()
    with allow_partial_results(getattr(args, "allow_partial", False)):
        if args.checkov_json:
            checkov_output = checkov_runner.load_checkov_json(
                args.checkov_json,
                args.iac_type,
                extra_types,
                require_complete=bool(
                    getattr(args, "fail_on_severity", None)
                    or getattr(args, "fail_on_any", False)
                    or getattr(args, "fail_on_suppressed", False)
                    or getattr(args, "fail_on_unmapped", False)
                ),
            )
        else:
            checkov_output = checkov_runner.run_checkov(
                args.path,
                args.iac_type,
                residency_env(policy, allowed),
                exclude=getattr(args, "exclude", None) or (),
                online=getattr(args, "online", False),
                timeout=getattr(args, "timeout", DEFAULT_CHECKOV_TIMEOUT),
                var_files=getattr(args, "var_files", None) or (),
                download_external_modules=getattr(args, "download_external_modules", False),
                secrets=bool(extra_types),
            )
    findings = checkov_runner.extract_failed_checks(checkov_output)  # also validates the shape
    if args.iac_type == "terraform":
        for region_check in (aws_region_unset_warning, gcp_region_unset_warning):
            region_warning = region_check(
                checkov_output, custom_checks_loaded=not args.checkov_json
            )
            if region_warning:
                print(region_warning, file=sys.stderr)
    skipped = checkov_runner.extract_skipped_checks(checkov_output)
    passed_checks = checkov_runner.extract_passed_checks(checkov_output)

    registry_dir = registry_path or default_registry_dir()
    loaded = load_registry_with_overlays(registry_dir, getattr(args, "registry_dirs", None) or [])
    for overlay, (entries, replaced) in loaded.file_stats.items():
        print(
            f"Registry overlay loaded: {overlay} ({entries} entries, "
            f"{replaced} override bundled checks)",
            file=sys.stderr,
        )
    active, unmapped = split_findings(findings, loaded.mappings)
    suppressed, suppressed_unmapped = split_findings(skipped, loaded.mappings)
    passed, _ = split_findings(passed_checks, loaded.mappings)  # unmapped passes are dropped
    (active, suppressed, passed), override_lines = _apply_severity_overrides(
        getattr(args, "severity_overrides", None) or {}, loaded, [active, suppressed, passed]
    )
    waived: list[EnrichedFinding] = []
    waiver_path = _waiver_path(args)
    waiver_line: list[str] = []
    if waiver_path:
        active, suppressed, waived, count = _apply_waiver_file(
            waiver_path, active, suppressed, getattr(args, "max_waiver_days", None)
        )
        waiver_line = [f"waivers: {waiver_path} ({count} entries)"]
    baselined: list[EnrichedFinding] = []
    baselined_unmapped: list[dict[str, Any]] = []
    remaining: list[EnrichedFinding] = []
    baseline_line: list[str] = []
    baseline_origin = ""
    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        baseline = load_baseline(baseline_path)
        for f in active:
            is_known = finding_key(f.check_id, f.resource, f.file_path) in baseline.keys
            (baselined if is_known else remaining).append(f)
        active, known = remaining, baselined
        new_unmapped: list[dict[str, Any]] = []
        for check in unmapped:
            key = finding_key(
                check.get("check_id", ""), check.get("resource"), check.get("file_path")
            )
            (baselined_unmapped if key in baseline.unmapped_keys else new_unmapped).append(check)
        unmapped = new_unmapped
        when = baseline.created.date().isoformat() if baseline.created else "unknown date"
        baseline_origin = (
            f"from {when} ({(_today() - baseline.created.date()).days} days old)"
            if baseline.created
            else "(date unknown)"
        )
        baseline_line = [
            f"baseline: {baseline_path} ({when}, {len(known)} known finding(s) matched, "
            f"{len(baselined_unmapped)} unmapped)"
        ]
    changed_line: list[str] = []
    matrix_inputs = None
    changed_ref = getattr(args, "changed_since", None)
    if changed_ref:
        scan_root = sarif_scan_root(args.path, args.iac_type)
        assert scan_root is not None  # --changed-since without --checkov-json always has a path
        changed = changed_files(scan_root, changed_ref)

        def inside(file_path: str | None) -> bool:
            resolved = (scan_root / (file_path or "").lstrip("/")).resolve()
            return in_changed_scope(resolved, changed, args.iac_type)

        matrix_inputs = ([*active, *baselined], suppressed, waived)
        groups = [active, suppressed, waived, baselined]
        raw = [unmapped, suppressed_unmapped, baselined_unmapped]
        hidden = sum(1 for g in groups for f in g if not inside(f.file_path))
        hidden += sum(1 for g in raw for f in g if not inside(f.get("file_path")))
        active, suppressed, waived, baselined = (
            [f for f in g if inside(f.file_path)] for g in groups
        )
        unmapped, suppressed_unmapped, baselined_unmapped = (
            [f for f in g if inside(f.get("file_path"))] for g in raw
        )
        print(
            f"Reporting only findings in {len(changed)} file(s) changed since {changed_ref}; "
            f"{hidden} finding(s) in unchanged files hidden",
            file=sys.stderr,
        )
        changed_line = [
            f"changed-since: {changed_ref} ({len(changed)} changed file(s); "
            f"{hidden} finding(s) in unchanged files hidden)"
        ]
    config_path = getattr(args, "config_path", None)
    weakening = [
        *([f"config: {config_path}"] if config_path else []),
        *(f"exclude: {pattern}" for pattern in getattr(args, "exclude", None) or ()),
        *waiver_line,
        *baseline_line,
        *override_lines,
        *changed_line,
        *(f"registry overlay: {path}" for path in loaded.overlay_files),
    ]
    return ScanFindings(
        active,
        unmapped,
        suppressed,
        suppressed_unmapped,
        checkov_version_of(checkov_output),
        loaded,
        passed,
        waived,
        weakening,
        baselined,
        matrix_inputs=matrix_inputs,
        checkov_summary=dict(checkov_output.get("summary") or {}),
        waiver_path=waiver_path,
        baseline_origin=baseline_origin,
        baselined_unmapped=baselined_unmapped,
    )


def default_registry_dir() -> Path:
    """Resolve the registry directory shipped inside the package."""
    return Path(__file__).parent.parent / "mapping"


def filter_findings_by_framework(
    findings: list[EnrichedFinding],
    framework_name: str,
) -> list[EnrichedFinding]:
    """Keep only articles in the selected framework and scope risk text."""
    if framework_name == "all":
        return findings

    target_framework = Framework(framework_name.upper())
    filtered_findings: list[EnrichedFinding] = []
    for finding in findings:
        articles = [
            article for article in finding.articles if article.framework == target_framework
        ]
        if articles:
            filtered_findings.append(
                replace(
                    finding,
                    articles=articles,
                    risk_explanation=scope_risk_text(
                        finding.risk_explanation, target_framework.value
                    ),
                )
            )
    return filtered_findings
