"""Cross-cutting constants shared by the CLI, the scanner, and tooling.

Domain-specific constants live next to their consumers instead (AWS region
policy in :mod:`tf_eu_guard.regions`, registry schema in
:mod:`tf_eu_guard.mapping.schema`, regulatory data in
:mod:`tf_eu_guard.mapping.requirements`, report styling in
:mod:`tf_eu_guard.reporting.styles`); only what crosses module boundaries
belongs here. Import this module — never re-type these values — so the CLI's
argparse choices and the Checkov runner's dispatch can't drift apart.
"""

#: IaC types tf-eu-guard can scan, mapped to Checkov's ``--framework`` values.
#: The single source of truth for the CLI's ``--iac-type`` choices and the
#: runner's dispatch (tools/smoke_check.py reads it too).
SUPPORTED_IAC_TYPES = ("terraform", "terraform_plan", "kubernetes")

#: Documented exit codes (see README "CI/CD Gating"). They let a pipeline
#: tell "the scan found blocking issues" apart from "the tool itself
#: failed to run" — a distinction the old binary 0/1 exit conflated.
#:   0 = scan ran, no blocking findings
#:   1 = scan ran, blocking findings found (--fail-on-* threshold met)
#:   2 = invalid invocation or configuration (bad flags, malformed
#:       registry, unusable Checkov JSON input)
#:   3 = scanner/runtime failure (Checkov itself crashed, registry failed
#:       to load, unexpected internal error)
#: argparse's own rejection of bad flags also exits 2, matching this table.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INVALID_INPUT = 2
EXIT_RUNTIME_FAILURE = 3

#: Report formats the CLI's ``--output`` accepts. ``all`` writes the dev,
#: security and auditor HTML files together (see ``--output-dir``); ``sarif``
#: emits a SARIF 2.1.0 document to stdout for GitHub Code Scanning.
OUTPUT_FORMATS = ("dev", "security", "auditor", "json", "sarif", "all")

#: Compliance-regime filters for the CLI's ``--framework`` — which regulatory
#: regime to *report* on. Unrelated to ``--iac-type`` (what to scan).
FRAMEWORK_FILTERS = ("nis2", "gdpr", "all")
