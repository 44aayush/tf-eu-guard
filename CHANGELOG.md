# Changelog

Notable changes to tf-eu-guard. Entries follow
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions; the
registry has changed in ways worth tracking beyond commit messages
(new provider registries, custom checks ported to Kubernetes, the
terraform_plan fix), so this starts now rather than reconstructing
history later. Versions follow the git tags/`__version__` at each
release point.

## [Unreleased]

### Added

- `--no-discovery` (and `scan(no_discovery=True)`) skips `.tf-eu-guard.yaml` and
  `.tf-eu-guard-waivers.yaml` in the scan root, so a pull request cannot weaken its own gate by
  committing them; `--config` and `--waivers` still apply and each ignored file is named on stderr
  (TEG-01).
- `--max-waiver-days N` (config `max_waiver_days`, `scan(max_waiver_days=)`, Action input `max-waiver-days`)
  refuses waivers that expire more than N days ahead, so their findings stay active, and a waiver without a
  `file` pattern now warns that it matches the resource in every file (TEG-01). Opt-in; exit codes are
  unchanged unless the option is set.
- A Terraform scan warns on stderr when AWS resources were scanned but no `provider "aws"` block sets a
  region (the residency checks cannot tell where they deploy), and a directory scan warns when hidden
  directories such as `.prod/` hold source files that Checkov skips (TEG-05). Exit codes are unchanged.
  The region warning also fires on a live scan with no `provider "aws"` block, where every EUGUARD check is
  UNKNOWN and no EUGUARD result exists; only `--checkov-json` input stays silent without one.
- `provenance.commit` is no longer null in the Action: the Action resolves the scanned checkout's HEAD on the
  runner (`git rev-parse HEAD` in the scanned directory; on `pull_request` that is the merge commit) and
  passes it as `TF_EU_GUARD_COMMIT`, falling back to `GITHUB_SHA` when that directory is not a repository.
  The value is used when git is unavailable and it is a 40- or 64-character lowercase hex id, and the new `provenance.commit_source` (`git`, `environment` or null) says which
  one supplied it (TEG-13).

### Changed

- JSON object schema v3 (`schema_version: "3"`): adds `provenance.commit_source`. The v2 schema closed
  `provenance`, so a v0.9 validator rejects the new key; consumers that check `schema_version` must accept
  "3". `--baseline` and `diff` still read "1", "2" and "3" reports.
- The Action no longer auto-discovers `.tf-eu-guard.yaml` or `.tf-eu-guard-waivers.yaml` in the scanned
  directory: it passes `--no-discovery` unless the new `discover-config` input is `true`. Use `config`
  or, on pull requests, `trusted-config` instead (TEG-01). Behaviour change for workflows that relied on discovery.
- A gated `--checkov-json` scan (`--fail-on-severity`, `--fail-on-any`, `--fail-on-suppressed` or
  `--fail-on-unmapped`) now exits 3 when the file is empty or incomplete (no positive integer
  `summary.resource_count`: missing summary, missing key, a string, a boolean or 0), so a truncated or
  empty file cannot pass a gate; a forged file with a positive count can still pass, since the gate is only
  as trustworthy as the file's producer. `--allow-partial` keeps the warning and ungated runs only warn
  (TEG-09). A file with no `EUGUARD_*` result only warns, since the custom checks are AWS-only.

### Fixed

- `--framework` filtering returns new findings instead of rewriting `articles` and `risk_explanation` on the
  caller's objects, so findings returned by `scan()` no longer change under the caller (TEG-17).
- The unset-AWS-region warning is no longer printed when the Checkov output holds no `EUGUARD_*` result at
  all (the custom checks did not run, so the claim cannot be made) (TEG-05).
- The hidden-directory warning no longer follows symlinked hidden directories, also ignores
  `.terragrunt-cache`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache` and `.circleci`, and applies
  `--exclude` inside the hidden directory too (TEG-05).
- `--max-waiver-days` lists a too-long waiver as "not applied" only when it decided the outcome: a finding
  that another in-range waiver covers no longer produces the warning (TEG-01).
- The Action accepts `path: ${{ github.workspace }}` (the bare workspace, no trailing slash) and the same
  value for its other workspace inputs; it was rejected as an absolute path outside the workspace.
- `--changed-since` keeps Terraform findings in the module directory, parent directories and
  subdirectories of a changed `.tf`, `.tfvars`, `.hcl`, `.tfvars.json` or `.tf.json` file, so changing a variable default no
  longer hides the resources it affects in untouched files; other IaC types stay file-granular (TEG-02).
- Documentation no longer says scanned code is only read and never executed (Checkov evaluates
  Terraform expressions), that `--var-file` is unsupported, or that residency checks cover Azure and GCP;
  the registry typo "weakensing" is fixed (TEG-05, TEG-07, TEG-11, TEG-12).

### Security

- The Docker base image digest is refreshed (python:3.12-slim, fewer HIGH OS CVEs) and CI gets an
  `image-scan` job that builds the image and fails on fixable HIGH or CRITICAL vulnerabilities with a
  pinned, checksum-verified trivy; the one remaining fixable CVE is a dated exception in
  `.trivyignore.yaml` (TEG-06).
- The Action's `provenance.commit` lookup can no longer be redirected: `git rev-parse` runs with the
  inherited `GIT_*` variables removed and `safe.bareRepository=explicit` (a bare repository planted under
  the scanned path is ignored), and the HEAD is used only when the repository's top level is the workspace
  or inside it; otherwise `GITHUB_SHA` is the fallback. Test git helpers also drop `GIT_*` from their
  environment.
- The Action merges the container's stderr into stdout and wraps both in a random
  `::stop-commands::` token that is resumed after the scan, so workflow commands printed by the
  scanned code are not interpreted while the container runs (TEG-03).
- Terminal and stderr output escapes control characters (newline, ESC, C1, bidi overrides) in
  resource names, file paths, check text, waiver fields, weakening lines and module sources taken
  from the scanned checkout, so a crafted name can no longer forge `::error::` annotations in a
  GitHub Actions log or repaint the terminal (TEG-03). Values are escaped, never dropped. The same
  applies to untrusted CSV columns, Markdown output, and relayed Checkov stderr (indented and escaped
  per line); Rich no longer expands `:emoji:` codes inside names.
- The Action fails with exit 3 if it cannot create a 32-hex stop-commands token, instead of running
  the container unbracketed.
- The Action validates the `path` and `checkov-json` inputs like `config`, `waivers` and `baseline`: a
  `..` segment or an absolute path outside the workspace exits 2, and workspace-relative values are
  passed to the CLI as `$GITHUB_WORKSPACE/<path>` (TEG-15).
- The Action verifies the build-provenance attestation of the image it pulls by tag (`gh attestation
  verify`, signed by `publish.yml`) and runs it by digest; if the pull, digest lookup or verification
  fails it builds the image locally and the notice names the failed stage (pull, digest, gh missing or
  attestation; gh's own output is not printed). New input `verify-image` (default true) turns this off
  only for an explicit `false`, `0` or `no` (any case); a typo keeps it on. An explicit `image` input is
  unchanged (TEG-04).

## [0.9.0] - 2026-11-18

### Added

- Python API: `tf_eu_guard.scan(...)` returns a typed `ScanResult` (findings, requirements,
  provenance) without printing to stdout or exiting; the package ships `py.typed`. The CLI and the API share
  one argument and scan pipeline (`prepare_scan_args`, `run_scan`).
- Provenance: the JSON object gains `provenance` (tool and Checkov versions, registry SHA-256 and
  files, git commit (HEAD; uncommitted changes are not detected), effective options, resources scanned, check counts) and the
  auditor report a "Provenance" section. New `--evidence-dir DIR` writes `dev.html`,
  `security.html`, `auditor.html`, `report.json`, `report.sarif`, `summary.md` and a
  `manifest.json` with a SHA-256 per file; it refuses an existing non-empty directory (exit 2).
- GitHub Action: new inputs `config`, `trusted-config` (read-only mount from outside the checkout,
  so a pull request cannot change the settings in it; keep it self-contained, because files it references must be in the workspace and are controlled by the pull request, and inline `checkov:skip` comments still remove findings unless `fail-on-suppressed` is set), `waivers`, `baseline` and `job-summary` (default
  `true`, appends the Markdown summary to the job summary); new outputs `critical`, `high`,
  `medium`, `low`, `info`, `unmapped`, `suppressed`, `waived`, `baselined` and `total`.
  `trusted-config` must be outside the workspace. Symlinks planted by the scan container are
  never followed or copied back.
- An explicit `--config FILE` now disables `.tf-eu-guard-waivers.yaml` auto-discovery, so a
  trusted config cannot be undercut by a waiver file in the scanned code (`--waivers` and the
  config's `waivers:` key still apply).
- `--output markdown` (summary) and `--output csv` (one row per finding and article; formula-like
  cells are prefixed with `'`), to stdout or `--output-file`. `--summary-file FILE` writes the
  Markdown summary and `--counts-file FILE` writes `key=value` counts (critical..info, unmapped,
  suppressed, waived, baselined, total) in addition to any `--output`, without changing stdout.
- `--secrets` adds Checkov's `secrets` framework (Terraform, Terraform plan, Kubernetes and
  `--checkov-json`). New `registry-secrets.yaml` maps the 19 `CKV_SECRET_*` checks Checkov 3.4.5
  names to NIS2 Art. 21(2)(e) and GDPR Art. 32(1)(b), HIGH. Secret values, code excerpts and
  Checkov's secret hash are dropped on load and never reach any report; parsing errors in the
  secrets scan fail closed.
- `--var-file FILE` (repeatable; config key `var_files`) passes Terraform variable files to
  Checkov so `var.*` values resolve. `--download-external-modules` lets Checkov fetch remote
  modules (stderr note; not available in the GitHub Action's `--network none` container).
  Both are Terraform source scans only; a missing var file exits 2.
- `--changed-since REF`: report only findings in files changed since a Git ref (committed
  and staged; unstaged and untracked changes are not included); hidden findings are counted on stderr and in the scan settings. Not
  valid with `--checkov-json` or `terraform_plan`.
- `.tf-eu-guard.yaml` project configuration (discovered in the scan root, or `--config FILE`;
  `--no-config` ignores it). Keys mirror the flags; CLI overrides config, list keys
  concatenate; new `severity_overrides` map re-grades mapped findings. See
  `docs/configuration.md`.
- "Scan settings that reduce findings": excludes, the loaded waiver file, severity
  overrides, registry overlays, the baseline, `--changed-since` and the config file are listed in the dev terminal header,
  all three HTML headers, JSON `scan.weakening_settings` and SARIF
  `run.properties.weakeningSettings`.
- `--waivers FILE` (default `.tf-eu-guard-waivers.yaml` in a source scan's root): reviewed,
  expiring waivers (owner, reason, expiry) for mapped findings. Waived findings leave the
  gate, including `--fail-on-suppressed`, but are listed in every report (JSON `waived[]`,
  SARIF `external` suppression, requirement matrix). See `docs/waivers.md`.
- `--baseline FILE`: findings already in an earlier JSON report (matched by check ID,
  resource and file, not line) are shown as "Known (in baseline)" in every report (JSON
  `baselined[]`, SARIF `baselineState`) and leave the `--fail-on-*` gate; the baseline's age
  is printed on stderr and recorded in the scan settings.
- `tf-eu-guard diff OLD.json NEW.json [--json]` lists new, fixed and unchanged findings (baselined findings count as present);
  exit 1 when new findings exist.
- JSON array entries carry a `baselined` flag; the object format gains a required
  `baselined` array.
- `--show-unmapped` lists unmapped Checkov findings (check ID, name, resource, file,
  lines) in the dev terminal report and the dev, security and auditor HTML reports.
- `--fail-on-unmapped` exits 1 when any active (not inline-suppressed) unmapped
  Checkov finding exists.
- `tf-eu-guard explain CHECK_ID` prints the registry entry (severity, articles,
  risk, remediation) for a check; unknown IDs exit 2.
- `--registry-dir DIR` (repeatable) overlays your own `*.yaml` registry files on
  the bundled registry; later definitions win per check ID, and each loaded
  overlay is reported on stderr. Overlay `POLICY` articles may use any title.
- `tf-eu-guard registry validate [DIR ...]` validates overlay directories, or
  the bundled registry when no directory is given.
- Requirement evidence matrix: passed checks are now read from Checkov output and
  counted per NIS2/GDPR requirement (15 rows with `--framework all`, otherwise only that framework's rows: ran, passed, failed, suppressed,
  waived; check results, no score). It appears in the auditor report ("Requirement
  evidence") and in the JSON object as `requirements`.
- JSON object schema v2 (`schema_version: "2"`): adds `requirements`, `registry`
  (`overlays`, `overridden`) and `waived`. The schema now ships inside the package
  at `tf_eu_guard/schemas/report.schema.json` (`tf_eu_guard.REPORT_SCHEMA_PATH`);
  it moved from `tests/schemas/`.

### Changed

- README code examples use plain fenced Markdown blocks.
- The legacy `--output json` array now also contains waived and baselined entries, flagged `waived: true` / `baselined: true`; consumers that treat every unsuppressed entry as active must check these flags.

### Fixed

- `--output csv` now prints the `Scan settings that reduce findings:` block on stderr when excludes, waivers, severity overrides or similar settings are active (stdout stays pure CSV)
- The stderr lines `N finding(s) waived by ...` and `N finding(s) match the baseline ...` now count findings after the `--framework` filter
- Git hardening: git runs with `core.fsmonitor` and hooks disabled, a scrubbed `GIT_*` environment and a 10 s timeout, so scanning a repository with a hostile `.git/config` no longer runs its commands; tf-eu-guard runs only `git rev-parse` and `git diff --name-only` (committed/staged), and never runs commands that compare working-tree file contents, because a hostile repo config can attach commands (filter drivers) to those; provenance's git call now runs only when an output needs it
- `LOG_LEVEL` is no longer passed to Checkov, so it always runs at its default WARNING level
- GitHub Action: reports are no longer copied through symlinks committed into the workspace
  (directory or file destinations exit 2), a committed symlink at an upload target (`*.html` in
  the output directory, `output-file`, the SARIF file) exits 2 with uploads disabled, and `trusted-config` is resolved with `readlink -f`
  so a symlink into the checkout is rejected.

## [0.8.1] - 2026-11-17

### Fixed

- The published container image now carries OCI labels (`image.source`,
  `title`, `description`, `licenses`, plus `version` and `revision` set at
  build time), so GHCR links the package to the repository and it appears in
  the repo's Packages sidebar.

## [0.8.0] — 2026-11-17

- CLI: `--version`; `--fail-on-severity` accepts any case; `--timeout SECONDS` (default 600, 0 disables) bounds Checkov and exits 3 on expiry; Checkov output is decoded as UTF-8 explicitly; `--checkov-json` (file or stdin) detects UTF-8 and UTF-16 byte-order marks; failures writing a report are exit 2, not 3; fixed the exit-code comment for a malformed registry.

- Action: new `artifact-name` and `timeout` inputs; boolean inputs accept `true`, `1` or `yes` in any case; the workspace is mounted read-only at its host path so absolute runner paths work (absolute output paths under the workspace are accepted); `output` now defaults to `dev` and `path` is no longer marked required; Linux-with-Docker runners are documented as required (T-37).
- Workflows: concurrency groups (pull-request runs cancel, publish never does), `timeout-minutes` on every job, documented permissions, no template expressions in `run` scripts, Dependabot cooldown, and zizmor (hashed CI lock) plus actionlint (sha256-verified release) in the lint job. The e2e workflow uploads SARIF for the vulnerable fixtures only on manual runs, under `e2e-*` categories. Added `CODEOWNERS`, a pull-request template and issue templates; removed the obsolete `tests/run_all_tests.sh` and `tests/cleanup_legacy_files.sh` (T-36, T-39).
- Dependencies: Checkov pin raised from 3.3.29 to 3.4.5 (suite and smoke checks pass); it still pins asteval 1.0.6 and ecdsa has no fix, so the three bounded advisory exceptions stay with review moved to 2026-12-17 and expiry to 2027-02-17. Recommendation recorded: ask upstream Checkov to raise the asteval pin (T-20).
- Locks: `requirements.lock` is now universal (platform and Python markers, resolved from 3.11.5), so it covers the Python 3.11 to 3.14 and Windows/macOS matrix as well as the Docker image's 3.12; a new hashed `requirements-dev.lock` holds the test and lint tools; `requirements-ci.lock` is resolved for 3.12. All are generated by `uv` through `tools/compile-locks.sh`, and the manual typing-extensions workaround in `requirements-ci.in` is gone. soupsieve and filelock moved to fixed versions (T-26, T-27).
- CI: lint, test and example-scan jobs install the hashed locks with `--require-hashes`, then the project with `--no-deps`; a new `lock-check` job regenerates all locks and fails on any diff. Regeneration command is in CONTRIBUTING.md (T-26, T-27).
- Action: the scan container now runs with `--network none`, `--read-only` plus a `/tmp` tmpfs, `--cap-drop ALL` and `no-new-privileges`; the workspace is mounted read-only and reports are written to a separate directory and copied back. `output-dir`/`output-file` must be workspace-relative without `..` (T-15). Dependency exception records gained a `reachability` note.
- Action: pulls `ghcr.io/44aayush/tf-eu-guard:<action ref>` first and falls back to a local build; new `image` input to pin by digest. Release tags publish that image with provenance and SBOM attestations (T-16).
- `upload-sarif` updated to github/codeql-action v4.39.3; every SHA pin now has a version comment; README example pins match the workflows (T-17).
- Publish workflow runs the CI workflow first and rejects tags not reachable from `origin/main`; Dependabot covers the Docker base image; CI tests Windows and macOS; the dev pre-commit hook is cross-platform, no longer rewrites files and matches the CI lint job; the sdist is limited to an explicit include list (T-18, T-19, T-23, T-24, T-25).
- SARIF: rules now carry `help` (text and Markdown), `properties.tags` and `properties.security-severity`; results carry `partialFingerprints["tfEuGuard/v1"]`; out-of-repository files get a root-level location instead of empty `locations`.
- Coverage labels: NIS2 Art. 21(2)(h), 21(2)(j) and GDPR Art. 32(1)(a) are now Partial; NIS2 21(2)(f) and GDPR 32(1)(d) use a new "Process evidence" label.
- Checkov runs with `--skip-download` by default (no Prisma Cloud request, no "Documentation" links); `--online` opts back in. `BC_*`, `PRISMA_*` and `CKV_IGNORE*` variables are always removed from Checkov's environment (T-09).
- Symlink and `*.tf.json` guards skip directories Checkov skips; escaping links to files Checkov does not read only warn (T-10). New repeatable `--exclude`/`--skip-path` passed to Checkov and honoured by the guards (T-11).
- Warning for remote Terraform module sources that are not analysed; `CKV_TF_1`/`CKV_TF_2` mapped to NIS2 Art. 21(2)(d) (T-12).
- Regions: added `ap-east-2`, `ap-southeast-6` and isolated-partition regions; new `tools/check_region_drift.py` compares the table with botocore.

### Added

- Inline `checkov:skip` suppressions are no longer invisible (T-01). The
  `results.skipped_checks` list is read and every report (dev terminal, dev,
  security and auditor HTML, JSON, SARIF) shows suppressed checks with check
  ID, resource, file, lines and stated reason. JSON entries gain `suppressed`
  and `suppression_reason`; SARIF results carry `suppressions` of kind
  `inSource`. Suppressed findings are not counted as active findings and do not
  trip `--fail-on-severity` / `--fail-on-any`.
- `--fail-on-suppressed` exits 1 when any mapped finding is suppressed inline;
  `--framework` applies to suppressed findings too. See
  `docs/limitations.md`.
- `--residency-policy {eu-eea,eusc,custom}` and `--allowed-regions` (GitHub
  Action inputs `residency-policy`, `allowed-regions`) make the AWS region
  policy configurable (T-06). The policy reaches the Checkov subprocess via
  `TF_EU_GUARD_RESIDENCY_POLICY` / `TF_EU_GUARD_ALLOWED_REGIONS` (ambient
  values are discarded; an invalid value fails closed to EUSC-only). With
  `--checkov-json` the flags are ignored and a warning is printed.
- GitHub Action input `fail-on-suppressed` (maps to `--fail-on-suppressed`).
- `EUGUARD_POLICY_002`: resource-level residency policy check covering the
  top-level `region` argument of any `aws_*` resource, DynamoDB and Secrets
  Manager replicas, ECR replication destinations and Backup copy-action vault
  ARNs. `EUGUARD_GDPR_003` is the matching hedged Chapter V review signal for
  known third-country regions (T-07). S3 replication destinations are not
  evaluated (bucket ARN regions are not statically known).

- `--checkov-json` now fails on `summary.parsing_errors > 0` (as source scans do) and warns on a Checkov version mismatch and on missing `EUGUARD_*` checks (T-08). `--allow-partial` downgrades parsing errors to a warning in both modes.
- `--output json` honours `--output-file` (UTF-8). New `--json-format {array,object}` (T-14): `object` is a versioned document (`schema_version: "1"`) with line ranges, check names, risk text, remediation, unmapped and suppressed entries; schema in `tests/schemas/report.schema.json`. `array` stays the default and is deprecated; the default changes to `object` in a future release.

### Changed

- Breaking-ish: the default residency policy is now `eu-eea` (EU/EEA commercial
  regions plus the Sovereign Cloud) instead of EUSC-only; `eu-central-1` now
  passes by default. Use `--residency-policy eusc` for the old behaviour.
- `EUGUARD_GDPR_001` renamed `EUGUARD_POLICY_001` and its mapping changed to
  `Policy RESIDENCY-001`. `EUGUARD_GDPR_001` remains as a deprecated alias
  entry in the registry and will be removed in the next release.

### Fixed

- Windows: scans no longer fail when the target is on a different drive than
  the Python environment; Checkov's working directory falls back to the
  target drive's root (T-02).
- Windows: the default `dev` report no longer crashes when output is
  redirected; stdout/stderr are reconfigured to UTF-8 and report files are
  written as UTF-8 (T-03).
- `EUGUARD_NIS2_001`: function calls and indexed traversals over Terraform
  references (`jsondecode(...)["k"]`, `random_password.db[0].result`,
  `var.m["k"]`, `try(...)`, `sensitive(...)`) are no longer flagged as hardcoded
  secrets; literals that resemble traversals (`db_admin.Password1`) or mix text
  with interpolations (`prod-${var.env}-Hunter2`) are now flagged (T-04).
- `EUGUARD_NIS2_002` (Kubernetes and the shared CodeBuild path): added `PASS`,
  `PASSPHRASE`, `DSN`, `CONNECTION_STRING`, `PAT` and `WEBHOOK` name tokens;
  excluded `PUBLIC_KEY`, `*_KEY_PREFIX`, `*_TTL`, `*_LENGTH`, `PARTITION_KEY`,
  `SORT_KEY`; values with `scheme://user:password@host` and Slack webhook URLs
  are flagged under any name; SOPS-encrypted `Secret` manifests are skipped (T-05).

## [0.7.1] — 2026-11-07

### Changed

- The development pre-commit hook now runs Ruff formatting, Ruff checks, and
  mypy; pytest remains part of the GitHub Actions test job rather than the
  local commit hook.
- Mypy typing issues in the documentation-count and dependency-exception
  tools, plus the terminal and SARIF report tests, were corrected.

## [0.7.0] — 2026-10-18

### Changed

- Project version and current release examples are now `0.7.0`, including the
  GitHub Action and pre-commit references.
- GitHub Actions workflows now run on explicitly selected Ubuntu 24.04 runners
  instead of the moving `ubuntu-latest` label.
- Removed the standalone Docker image-build command from the project task and
  release-validation documentation; the Action's runtime behavior is unchanged.

## [0.6.0] — 2026-10-17

### Added

- A separate `EUGUARD_GDPR_002` third-country transfer-review signal, keeping
  the EUSC sovereignty policy (`EUGUARD_GDPR_001`) separate from GDPR Chapter V
  review. Commercial EU regions remain policy findings without an Art. 44
  citation.
- Live secret-shape fixtures and assertions covering the supported custom
  secret check plus Checkov's provider, EC2 user-data, and Lambda environment
  replacements.
- A clean-install CI job that builds a wheel, installs it non-editably in a
  fresh environment outside the checkout, verifies bundled registries and
  custom checks, and scans a compliant fixture.

### Changed

- GitHub Action report uploads now follow the effective `output-dir` and
  `output-file` destinations, upload only HTML-producing outputs, and pass the
  exact SARIF file to Code Scanning. Action e2e coverage covers default and
  custom destinations.
- CI and release tooling (`build`, `cyclonedx-bom`, `pip-audit`, and related
  build dependencies) is installed from the hashed `requirements-ci.lock`
  lockfile.
- The documented `EUGUARD_NIS2_001` scope now matches its supported
  database/cache and CodeBuild fields; unsupported provider, user-data, and
  Lambda shapes are documented with their independently verified stock checks.
- The pre-commit hook and README now consistently document its HIGH-or-worse
  mapped-finding threshold.
- Demo documentation now describes the CSS severity bars, actual auditor
  article/resource tables, and framework aggregation from JSON output.
- Project version and release references are now `0.6.0`.
- Auditor mapping rationale links resolve to the versioned public documentation,
  including from pip-installed reports.
- Documentation and CI use the timestamped `reports/*_report_*.html` contract.

### Fixed

- HTML `--output-file` destinations now create missing parent directories,
  matching SARIF behavior.
- Registry validation now converts non-string and unhashable YAML mapping keys
  into contextual `RegistryValidationError` failures instead of leaking
  `TypeError`.
- The hashed CI tooling lock now explicitly includes `typing-extensions`, a
  conditional dependency required by `cyclonedx-python-lib` on Python 3.12.

## [0.5.0] — 2026-10-02

### Added

- Immutable GitHub Action references, Dependabot updates, runtime dependency
  locking, `pip-audit`, and CycloneDX SBOM generation in CI and releases.
- Release builds and PyPI publishing run as separate least-privilege jobs.

### Changed

- The package and documented Action/pre-commit references now use `0.5.0`.
- Auditor mapping rationale links resolve to the versioned public documentation,
  including from pip-installed reports.
- Documentation and CI use the timestamped `reports/*_report_*.html` contract.

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
  from file/line range). Mapped rules/results carry the NIS2/GDPR articles,
  registry remediation, and mapped metadata in `properties`; unmapped rules/
  results carry identity/location metadata and `mapped: false` without
  registry remediation. Output goes to stdout (like `--output json`) or to
  `--output-file`. Unmapped Checkov findings ship as note-level results. The
  document is validated against the official OASIS
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

- Historical Checkov 3.3.13 wrapper (pinned for reproducible scans at the
  initial release; current releases pin Checkov 3.3.29) with
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

[Unreleased]: https://github.com/44aayush/tf-eu-guard/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/44aayush/tf-eu-guard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/44aayush/tf-eu-guard/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/44aayush/tf-eu-guard/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/44aayush/tf-eu-guard/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/44aayush/tf-eu-guard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/44aayush/tf-eu-guard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/44aayush/tf-eu-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/44aayush/tf-eu-guard/releases/tag/v0.1.0
