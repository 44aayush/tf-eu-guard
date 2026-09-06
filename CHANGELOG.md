# Changelog

Notable changes to tf-eu-guard. Entries follow
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions; the
registry has changed in ways worth tracking beyond commit messages
(new provider registries, custom checks ported to Kubernetes, the
terraform_plan fix), so this starts now rather than reconstructing
history later. Versions follow the git tags/`__version__` at each
release point.

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

[0.3.0]: https://github.com/44aayush/tf-eu-guard/compare/0.2.2...0.3.0
[0.2.2]: https://github.com/44aayush/tf-eu-guard/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/44aayush/tf-eu-guard/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/44aayush/tf-eu-guard/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/44aayush/tf-eu-guard/releases/tag/v0.1.0
