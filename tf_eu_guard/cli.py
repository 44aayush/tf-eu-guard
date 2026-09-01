"""CLI entry point for tf-eu-guard."""

import argparse
import sys
from pathlib import Path


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="tf-eu-guard",
        description="EU compliance security linter for Terraform (source, plan JSON) "
                    "and Kubernetes (NIS2 + GDPR)",
    )
    parser.add_argument(
        "command",
        choices=["scan", "version"],
        help="Command to execute",
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Path to IaC directory to scan",
    )
    parser.add_argument(
        "--iac-type",
        choices=["terraform", "terraform_plan", "kubernetes"],
        default="terraform",
        help="IaC language to scan (default: terraform). Passed to Checkov's "
             "--framework flag. NOTE: unrelated to --framework below, which "
             "selects the compliance regime to REPORT (NIS2/GDPR). "
             "'terraform_plan' scans a terraform show -json output file via "
             "--checkov-json, not a directory.",
    )
    parser.add_argument(
        "--output",
        choices=["dev", "security", "auditor", "json", "all"],
        default="dev",
        help="Report format (default: dev). 'all' writes the dev, security and "
             "auditor HTML files together (see --output-dir).",
    )
    parser.add_argument(
        "--framework",
        choices=["nis2", "gdpr", "all"],
        default="all",
        help="Compliance framework filter (default: all) — which regulatory "
             "regime to report on. Unrelated to --iac-type (what to scan).",
    )
    parser.add_argument(
        "--checkov-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="Use a pre-generated Checkov JSON file instead of running Checkov "
             "(use '-' to read from stdin). PATH becomes optional when this is set.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="For --output security|auditor, write the single HTML report here "
             "(default: scan-report.html / auditor-report.html). "
             "Ignored for dev, json and all.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for HTML report output (default: reports/; "
             "created if missing). For --output all, the three HTML files are "
             "written here with timestamped names.",
    )

    parser.add_argument(
        "--fail-on-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Exit with code 1 if any finding is at or above this severity "
             "(for CI/CD gating). Default: disabled (exit 0 unless an error occurs).",
    )
    parser.add_argument(
        "--fail-on-any",
        action="store_true",
        help="Exit with code 1 if any finding exists, regardless of severity.",
    )

    args = parser.parse_args()

    if args.command == "version":
        from tf_eu_guard import __version__
        print(f"tf-eu-guard version {__version__}")
        return 0

    if args.command == "scan":
        if not args.path and not args.checkov_json:
            parser.error(
                "scan command requires a PATH, or --checkov-json <file> (use '-' for stdin)"
            )

        # terraform_plan files are single JSON documents, not directories —
        # Checkov needs -f <file>, which only happens through --checkov-json.
        if args.iac_type == "terraform_plan" and not args.checkov_json:
            parser.error(
                "--iac-type terraform_plan requires --checkov-json <file> "
                "(the 'terraform show -json' output of a saved plan)"
            )

        # Execute the scan pipeline
        from tf_eu_guard.checkov_runner import (
            extract_failed_checks,
            load_checkov_json,
            run_checkov,
        )
        from tf_eu_guard.mapping.loader import enrich_findings, load_registry
        from tf_eu_guard.models import Framework

        try:
            # Step 1: Obtain Checkov results — from a pre-generated JSON if provided,
            # otherwise by running Checkov against the target directory.
            if args.checkov_json:
                checkov_output = load_checkov_json(args.checkov_json, args.iac_type)
            else:
                checkov_output = run_checkov(args.path, args.iac_type)
            findings = extract_failed_checks(checkov_output)

            # Step 2: Load compliance registry (all registry-*.yaml files)
            registry_path = Path(__file__).parent / "mapping"
            registry = load_registry(registry_path)

            # Step 3: Enrich findings with compliance mappings
            enriched = enrich_findings(findings, registry)

            # Step 4: Filter by framework if requested
            if args.framework != "all":
                target_framework = Framework(args.framework.upper())
                enriched = [
                    f for f in enriched
                    if any(a.framework == target_framework for a in f.articles)
                ]

            # Step 5: Generate report
            if args.output == "dev":
                from tf_eu_guard.reporting.dev_report import generate_dev_report
                generate_dev_report(enriched)
            elif args.output == "json":
                import json
                output = [
                    {
                        "check_id": f.check_id,
                        "severity": f.severity.value,
                        "resource": f.resource,
                        "file_path": f.file_path,
                        "articles": [{"framework": a.framework.value, "article": a.article} for a in f.articles]
                    }
                    for f in enriched
                ]
                print(json.dumps(output, indent=2))
            elif args.output in ("security", "auditor", "all"):
                # HTML report(s). 'all' writes the dev, security and auditor
                # files together; the single formats write just their own.
                from datetime import datetime, timezone

                from tf_eu_guard import __version__
                from tf_eu_guard.reporting.auditor_report import (
                    generate_auditor_report,
                )
                from tf_eu_guard.reporting.dev_html_report import (
                    generate_dev_html_report,
                )
                from tf_eu_guard.reporting.security_report import (
                    generate_security_report,
                )

                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                timestamp_suffix = datetime.now(timezone.utc).strftime("%d%m%Y%H%M")
                target = str(args.path) if args.path else f"checkov-json:{args.checkov_json}"

                # Default to reports/ directory
                out_dir = args.output_dir or Path("reports")
                out_dir.mkdir(parents=True, exist_ok=True)

                # kind -> (default filename, generator)
                generators = {
                    "dev": (f"dev_report_{timestamp_suffix}.html", generate_dev_html_report),
                    "security": (f"scan_report_{timestamp_suffix}.html", generate_security_report),
                    "auditor": (f"auditor_report_{timestamp_suffix}.html", generate_auditor_report),
                }
                kinds = (
                    ["dev", "security", "auditor"]
                    if args.output == "all"
                    else [args.output]
                )

                written = []
                for kind in kinds:
                    default_name, generator = generators[kind]
                    # --output-file only overrides the destination for a single format.
                    if args.output == "all":
                        out_path = out_dir / default_name
                    else:
                        out_path = args.output_file or (out_dir / default_name)
                    generator(
                        enriched,
                        target=target,
                        timestamp=timestamp,
                        version=__version__,
                        output_path=out_path,
                    )
                    written.append(out_path)

                label = "Reports" if len(written) > 1 else f"{args.output.capitalize()} report"
                print(f"{label} written ({len(enriched)} findings):")
                for out_path in written:
                    print(f"  {out_path}")

            # Step 6: CI/CD gating — exit non-zero if findings meet the threshold
            if args.fail_on_any:
                failing = list(enriched)
            elif args.fail_on_severity:
                from tf_eu_guard.models import Severity

                threshold = Severity(args.fail_on_severity)
                severity_order = [
                    Severity.INFO,
                    Severity.LOW,
                    Severity.MEDIUM,
                    Severity.HIGH,
                    Severity.CRITICAL,
                ]
                threshold_rank = severity_order.index(threshold)
                failing = [
                    f for f in enriched
                    if severity_order.index(f.severity) >= threshold_rank
                ]
            else:
                failing = []

            if failing:
                print(
                    f"Fail: {len(failing)} finding(s) at or above threshold "
                    f"({args.fail_on_severity or 'ANY'}) — see report above.",
                    file=sys.stderr,
                )
                return 1

            return 0

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
