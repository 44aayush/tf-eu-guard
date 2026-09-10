# Changelog

Notable changes to tf-eu-guard. Entries follow
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions; the
registry has changed in ways worth tracking beyond commit messages
(new provider registries, custom checks ported to Kubernetes, the
terraform_plan fix), so this starts now rather than reconstructing
history later. Versions follow the git tags/`__version__` at each
release point.

## [0.4.2] — 2026-09-11

### Changed

- **Skill documentation refresh** (`.claude/skills/tf-eu-guard/SKILL.md`) —
  rewritten to match the tool's current behavior, with every claim verified
  against the codebase: unmapped findings are tracked and reported (not
  dropped — `--output json` returns mapped findings only, while `dev`,
  `security`, and `sarif` output surface the unmapped count); SARIF 2.1.0
  output and `--output-file` are documented; severity levels include LOW
  (and INFO for gating); the Art. 44 EUSC-only data-residency policy,
  `examples/unmapped-aws/` fixture, GitHub Action, and pre-commit hook are
  all covered. No code changes.

## [0.4.1] — 2026-09-11

### Fixed

- **Checkov subprocess isolation** — `run_checkov()` now invokes Checkov as
  `[sys.executable, "-m", "checkov.main", ...]` instead of resolving a bare
  `checkov` via `PATH`, guaranteeing the Checkov installation in
  tf-eu-guard's own Python environment is used even when another global
  Checkov install would otherwise shadow it. Enforced by the regression
  test `test_run_checkov_invokes_own_interpreter`; the live-test skip
  conditions and `tests/run_all_tests.sh` likewise detect Checkov in the
  Python environment rather than on `PATH`.

### Verified

- The Action e2e workflow (`action-e2e.yml`) asserts specific expected
  check IDs (including `EUGUARD_GDPR_001`), not finding counts, and covers
  the empty `fail-on-severity` gating-disabled path.
- A region set by a variable with no default (and no tfvars) is
  explicitly classified by the fail-closed policy — now backed by a
  fixture and regression test rather than a docs claim.

## [0.4.0] — 2026-09-08

### Added

- **SARIF 2.1.0 output** (`--output sarif`) — each finding maps to a SARIF
  `result` (`ruleId` = check ID, `level` from severity, `physicalLocation`
  from file/line range) with the NIS2/GDPR articles, remediation, and
  mapped/unmapped metadata in `properties` on both the rule and the result.
  Output goes to stdout (like `--output json`) or to `--output-file`.
  Unmapped Checkov findings ship as note-level results tagged
  `mapped: false`. The document is validated against the official OASIS
  SARIF 2.1.0 JSON schema in `tests/test_sarif_report.py` (schema vendored
  under `tests/schemas/`; `jsonschema` added to the `dev` extras).
- **GitHub Action: `iac-type` input** — the Action was rewritten from
  `using: docker` to a composite action (same Dockerfile) and now supports
  every `--iac-type` the CLI does: `terraform` (default),
  `terraform_plan` (pass the plan file as `path`), and `kubernetes`.
- **GitHub Action: report artifacts and Code Scanning upload** —
  `upload-reports: true` uploads the generated HTML reports as a workflow
  artifact (`if: always()`, so they are retrievable exactly when the
  severity gate fails the scan), and `upload-sarif: true` (with
  `output: sarif`) uploads the SARIF to GitHub Code Scanning via
  `github/codeql-action/upload-sarif`.
- **Action e2e workflow** (`.github/workflows/action-e2e.yml`) — runs the
  actual Docker Action against fixtures for all three iac-types and asserts
  on specific expected check IDs (not finding counts), the article
  metadata in the SARIF, the HTML reports landing for the artifact, and
  that the default HIGH gate fails the scan step.
- **Registry wording audit** — all "violat*"/"non-compliant"/"breach"
  language across the four registry files was reviewed against the
  `docs/gdpr-mapping.md` no-overclaiming standard; six entries were
  reworded where config states were mislabeled as legal violations, and
  direct language was deliberately kept where the technical control
  failure is unambiguous (wildcard admin grants, unencrypted storage).
- **Wheel-content packaging test** (`tests/test_packaging.py`) — builds the
  actual wheel (`python -m build --no-isolation`, hatchling added to the
  `dev` extras) and asserts all four `registry-*.yaml` files and the
  `checks/` subpackage ship inside it, non-empty and parseable. A future
  packaging-config change that silently dropped them now fails CI instead
  of degrading every downstream scan to unmapped findings.
- **Guideline URL scheme validation** — guideline links in the security,
  dev-HTML, and terminal reports are now scheme-gated (`http`/`https` only)
  via `safe_guideline()` in `tf_eu_guard/reporting/_html_common.py`.
  HTML-escaping neutralizes markup characters but not URL schemes: a
  `javascript:` or `data:` guideline (possible via
  `--external-checks-dir` custom checks) previously rendered as a working
  clickable link; it now renders no link at all. URLs containing Rich
  markup-breaking characters are rejected too.

### Fixed

- **Empty `--fail-on-severity ''` is honored as "no gating"** — the GitHub
  Action's input description promised "empty disables gating," but the
  value passed through to argparse `choices` was rejected with exit 2. The
  flag now uses a custom argument type that maps `''` to "disabled" (with
  regression tests), and the composite Action omits the flag entirely when
  the input is empty.

- **Within-file duplicate registry keys are rejected** — `yaml.safe_load`
  silently keeps only the last definition when a check_id appears twice in
  one registry file, before any validation code runs. The loader now uses a
  duplicate-refusing SafeLoader subclass (`_UniqueKeyLoader`) that raises
  `RegistryValidationError` with the offending key and line number.
- **`EUGUARD_GDPR_001` region classification** — the check matched AWS's
  `eu-` string prefix, so `eu-west-2` (London, UK) and `eu-central-2`
  (Zurich, Switzerland) — GDPR third countries — passed as "EU-compliant."
  Prefix matching is replaced with an explicit allowlist; classification is
  fail-closed, so any region not on the allowlist — including unrecognized
  strings and unresolved `var.region` references (previously *unknown* and
  therefore absent from reports) — produces a finding. Scans of stacks
  pinned to London or Zurich will newly report a GDPR Art. 44 finding;
  that is the fix working, not a regression.

### Changed

- **Constants extracted into dedicated, domain-scoped modules** (internal
  refactor, no behavior change): `tf_eu_guard/constants.py` (CLI exit codes,
  supported IaC types, output/framework choices — the CLI's argparse choices
  are now derived from them instead of hand-retyped), `tf_eu_guard/regions.py`
  (the EUSC-only region policy table), `tf_eu_guard/mapping/schema.py`
  (registry schema constants), `tf_eu_guard/mapping/requirements.py`
  (NIS2/GDPR titles + the requirement coverage inventory, split out of the
  coverage model), and `tf_eu_guard/reporting/styles.py` (severity palettes —
  previously defined in three places — framework orderings, and the
  per-report stylesheets). Old import paths keep resolving via the importing
  modules.
- **`EUGUARD_GDPR_001` narrowed to EU Sovereign Cloud regions only** —
  the project is based on the AWS European Sovereign Cloud, so the check's
  allowlist now contains only `eusc-de-east-1` (verified against botocore's
  `aws-eusc` partition data). Commercial EU regions (`eu-central-1`
  Frankfurt, `eu-west-1` Ireland, `eu-west-3` Paris, `eu-north-1`
  Stockholm, `eu-south-1` Milan, `eu-south-2` Spain) now **fail** the
  compliance gate even though GDPR Art. 44 would permit them — a
  sovereignty policy stricter than the legal baseline, worded as such in
  the finding text. `examples/compliant-aws` now pins its providers to
  `eusc-de-east-1`.

## [0.3.0] — 2026-09-06

**Exit codes and the requirement-level coverage model — a CI pipeline
can now tell "we found problems" apart from "the tool is broken," and
an auditor can see which regulatory requirements are *actually*
automated vs. manual. Also adds `CHANGELOG.md`, `docs/architecture.md`
and `docs/limitations.md`.**

### Added

- **Explicit exit codes** (documented in the README's CI/CD Gating
  section): `0` = no blocking findings, `1` = blocking findings found,
  `2` = invalid invocation/configuration (bad flags, unusable
  `--checkov-json` input), `3` = scanner/runtime failure (Checkov
  crashed, the shipped registry failed to load). A malformed
  *user-supplied* input exits 2; a corrupted *shipped* registry file
  exits 3 — the registry is part of the tool, not the invocation.
- **Requirement-level coverage model** (`tf_eu_guard/mapping/coverage.py`):
  NIS2 Art. 21(2)(a)–(j) and GDPR Art. 32(1)(a)–(d) & Art. 44 classified
  as **Automated / Partial / Manual / Not covered** — by *requirement*,
  not by mapped-check count. 3 requirements are fully automated, 11
  partial, 1 manual (Art. 21(2)(a) — risk analysis is an organisational
  process a linter structurally cannot perform).
- **`docs/regulatory-coverage.md`** — generated from the registries by
  `tools/generate_coverage_doc.py` (never hand-edited), with a
  `--check` drift guard wired into CI alongside `check_doc_counts.py`.
- Tests: 14 new coverage-model tests and a CLI exit-code test suite
  (clean → 0, findings+gate → 1, missing input → 2, corrupted registry → 3,
  verified at process level).
- Repo docs: `CHANGELOG.md` (this file), `docs/architecture.md`
  (pipeline walkthrough, Checkov as a swappable detection backend) and
  `docs/limitations.md` (consolidated disclaimers), all cross-linked
  from the README.

## [0.2.2] — 2026-09-06

**Unmapped-findings policy, pre-commit hook, and the smoke-baseline
regression guard.**### Added

- **Unmapped findings are surfaced, never silently dropped.** Checkov
  failures with no registry mapping are reported as a count in every
  output format (dev/security/auditor reports, a stderr note alongside
  JSON output) and explicitly excluded from gating — severity is
  registry-authored, so an unmapped finding has no severity to compare.
  Includes the `examples/unmapped-aws/` fixture (S3 findings mixed with
  the unmapped `CKV_AWS_10`–`15` password-policy family).
- **Pre-commit hook** (`.pre-commit-hooks.yaml`): runs
  `tf-eu-guard scan --output dev --fail-on-severity HIGH` once against
  the repo root (`pass_filenames: false` — Checkov needs
  directory-level context).
- **Smoke-baseline regression guard** (`tools/smoke_baselines.json`,
  `tools/smoke_check.py`): expected mapped-finding counts for every
  vulnerable/compliant example pair in one single source of truth, read
  by CI, the local script, and the Claude Code hook. Born from the
  `c7e68f6` incident: a broken `terraform_plan` path silently returned
  0 findings while unit tests and CI stayed green because the CI smoke
  step scanned a hand-shaped fixture instead of the real example.
- **Claude Code PostToolUse hook** (`tools/hook_smoke_dispatch.py`):
  maps an edited file to the IaC types it can affect and runs only
  those smoke checks after each edit.
- `docs/check-mapping-table.md` documents the
  mapped-vs-deliberately-unmapped methodology.

### Changed

- Python 3.14 added to the CI test matrix.

## [0.2.1] — 2026-09-05

**Bugfix & hooks.**

### Fixed

- **`terraform_plan` scan path** (`checkov_runner.py`): plan scans now
  run Checkov against the real plan file (`checkov -f <plan.json>
  --framework terraform_plan`) and findings report `file_line_range:
  [0, 0]` (the plan is one JSON line) with reports omitting the line
  reference in that case. The earlier silent-0 failure mode is covered
  by regression tests and the smoke baselines introduced in 0.2.2.

### Added

- `--checkov-json` now accepts multi-check-type Checkov output (a JSON
  array) and extracts the `terraform` result automatically.
- CONTRIBUTING.md sections on smoke checks and the Claude Code hook.

## [0.2.0] — 2026-09-01

**Terraform plan scanning, Kubernetes support, and the Azure/GCP/K8s
registries.**

### Added

- **Terraform plan JSON scanning** (`--iac-type terraform_plan`):
  catches configuration as it will actually be applied
  (`terraform show -json` output). Reuses the same `CKV_AWS_*` registry
  IDs as source mode. Committed example fixture at
  `examples/vulnerable-aws-plan/`.
- **Kubernetes manifest scanning** (`--iac-type kubernetes`): the
  `CKV_K8S_*` namespace gets its own registry
  (`tf_eu_guard/mapping/registry-kubernetes.yaml`, 24 mappings — pod
  security context, RBAC, NetworkPolicy, secrets, resource limits,
  image hygiene, probes). Custom check `EUGUARD_NIS2_001` (hardcoded
  secrets) ported to Kubernetes via Checkov's external-check mechanism.
- **Azure and GCP registries** (`registry-azure.yaml` 23 mappings,
  `registry-gcp.yaml` 22 mappings) — the registry is glob-loaded per
  namespace, so no loader change was needed (`docs/DECISIONS.md` #8–9).
- GitHub Action publish workflow; vulnerable/compliant Kubernetes
  example fixtures.

## [0.1.0] — 2026-08-30

**Initial release.**

- Checkov 3.3.13 wrapper (pinned for reproducible scans) with
  enrichment against the NIS2 Art. 21(2) / GDPR Art. 32(1) mapping
  registry.
- AWS registry: 116 `CKV_AWS_*`/`CKV2_AWS_*` mappings, article
  citations verified against the directive/regulation text.
- Custom checks: `EUGUARD_GDPR_001` (non-EU provider regions → GDPR
  Chapter V / Art. 44), `EUGUARD_NIS2_001` (hardcoded secrets →
  Art. 21(2)(e) secure development).
- Report formats: dev (terminal), security dashboard (HTML), auditor
  article-by-article matrix (HTML), JSON.
- `--checkov-json` for pre-generated Checkov output, `--framework`
  filter, `--fail-on-severity` / `--fail-on-any` CI gating.

[0.4.2]: https://github.com/44aayush/tf-eu-guard/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/44aayush/tf-eu-guard/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/44aayush/tf-eu-guard/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/44aayush/tf-eu-guard/compare/0.2.2...0.3.0
[0.2.2]: https://github.com/44aayush/tf-eu-guard/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/44aayush/tf-eu-guard/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/44aayush/tf-eu-guard/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/44aayush/tf-eu-guard/releases/tag/v0.1.0
