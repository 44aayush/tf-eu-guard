# Review remediation, iteration 6, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-25 to T-29 on `version_0.10.0`: a trivy gate on the release image, a warning for the implicit JSON layout, tests for the two supply-chain tools, an `--unmapped-severity` gate option, and the emulator and snapshot follow-ups from iteration 5.

**Architecture:** A workflow-only change to `publish.yml`, pinned by workflow tests. Small CLI changes in `cli/parser.py`, `cli/reports.py`, `cli/gating.py`, `config.py` and `action.yml`, following the T-14 (`fail-on-unmapped`) pattern. Test-only work for `tools/` and `tests/emulator`.

**Tech Stack:** Python 3.11-3.14, argparse, pytest, GitHub Actions YAML.

**Spec:** REVIEW.md TEG-06/TEG-04 (release image scan), TEG-10 (`--unmapped-severity`), TEG-17 (implicit `--json-format`, 0%-coverage tools), section 7 "After iteration 5" (emulator follow-up), and the iteration-5 ledger's deferred minors. TASKS.md T-25 to T-29.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is the review venv. Never write a scratchpad absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- The gate stays clean after your last change: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, `mypy --ignore-missing-imports tf_eu_guard tools`, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1`.
- Every user-visible change gets a CHANGELOG entry under the unreleased section (`### Added` or `### Changed`).
- No default gate behaviour changes: with no new flag set, every exit code stays what it is today.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **The Action's cleared input:** `--unmapped-severity ''` disables the option and does not error, like `--fail-on-severity ''`. *Pinned by `test_unmapped_severity_empty_disables` (Task 4).*
2. **Inline-suppressed unmapped findings never count** under `--unmapped-severity`. *Pinned by `test_unmapped_severity_ignores_suppressed` (Task 4).*
3. **`--output all`** with an implicit JSON layout prints the deprecation warning exactly once. *Pinned by `test_implicit_json_format_warns_once_for_all` (Task 2).*
4. **Machine-readable stdout stays pure:** the warning goes to stderr only, and `json.loads(stdout)` still yields a list. *Pinned by `test_implicit_json_format_warns` (Task 2).*
5. **Pin drift between workflows:** the release trivy version and checksum must equal ci.yml's, so bumping one without the other fails. *Pinned by `test_publish_trivy_pin_matches_ci` (Task 1).*

---

### Task 1: Trivy gate on the release image (T-25, TEG-06/TEG-04)

**Files:** modify `.github/workflows/publish.yml` (job `image`), `tests/test_ci_workflows.py`, CHANGELOG.

Today the `image` job builds and pushes in one `docker/build-push-action` step, and nothing scans the image before it reaches GHCR.

- [ ] **Step 1: Write the failing tests** in `tests/test_ci_workflows.py`, using its existing YAML-loading helpers:
  - `test_publish_image_is_scanned_before_push`: in `jobs.image.steps`, a step whose `run` contains `trivy" image` (or `trivy image`) with `--exit-code 1`, `--severity HIGH,CRITICAL`, `--ignore-unfixed` and `--ignorefile .trivyignore.yaml` comes before the first step that uses `docker/build-push-action` with `push: true`.
  - `test_publish_trivy_pin_matches_ci`: the publish trivy install step's `env.TRIVY_VERSION` and `env.TRIVY_SHA256` equal those of ci.yml's `image-scan` job, and the step pipes through `sha256sum --check --strict`.
  - `test_publish_scan_build_does_not_push`: the build step that feeds the scan has `push: false` and `load: true` (or is a plain `docker build`).
- [ ] **Step 2:** Run `<venv>/bin/pytest tests/test_ci_workflows.py -q` and expect the three new tests to FAIL.
- [ ] **Step 3: Implement.** Before "Build and push image", add three steps:
  1. Build the image locally with the same `docker/build-push-action` SHA, `push: false`, `load: true` and tag `tf-eu-guard:release-scan`.
  2. Install trivy, copied verbatim from ci.yml's image-scan install step (same version, checksum and comment).
  3. Scan `tf-eu-guard:release-scan` with the flags in step 1.
  Add a YAML comment explaining that the scan blocks the push. The existing push step stays as it is.
- [ ] **Step 4:** Run the tests and expect PASS. Run `actionlint` if it is on PATH; otherwise note in the report that it was not run.
- [ ] **Step 5:** Add a CHANGELOG `### Changed` line, then commit `ci(publish): scan the release image with trivy before pushing (TEG-06)`.

### Task 2: Warn when the JSON layout is implicit (T-26, TEG-17)

**Files:** modify `tf_eu_guard/cli/parser.py` (`--json-format`), `tf_eu_guard/cli/reports.py`, and any other reader of `args.json_format` (grep for it). Docs that describe the default go in `docs/configuration.md` if they mention it. Tests go in the existing CLI JSON report test module (grep `json_format` in `tests/`). CHANGELOG.

**Interfaces:**
- Produces: `resolve_json_format(args: argparse.Namespace) -> str` in `tf_eu_guard/cli/reports.py`. It returns `"array"` or `"object"`, and `"array"` when the attribute is missing or `None`. Every reader uses it.

- [ ] **Step 1: Write the failing tests:**
  - `test_implicit_json_format_warns`: `scan <fixture> --output json --no-config` without `--json-format`. stderr contains exactly this line: `Warning: --json-format not given; using the deprecated 'array' layout. Pass --json-format object (recommended) or --json-format array to silence this warning; the default changes to 'object' in a future release.` `json.loads(stdout)` is a `list`.
  - `test_explicit_json_format_does_not_warn`: parametrised over `array` and `object`. stderr does not contain `--json-format not given`.
  - `test_implicit_json_format_warns_once_for_all`: with `--output all` (if `all` writes a JSON report; if it does not, assert that no warning appears and say so in the report), the warning appears exactly once.
  - `test_implicit_json_format_with_output_file`: `--output-file` set. The file holds a JSON list, and the warning is on stderr.
- [ ] **Step 2:** Run the new tests and expect FAIL.
- [ ] **Step 3: Implement.** Change the parser default to `None` and leave the help text's "(default: array)" as it is. Add `resolve_json_format`. Print the warning only when `--output` produces a JSON report and `args.json_format is None`.
- [ ] **Step 4:** Run the tests and expect PASS. Then run the full suite: existing tests that assert empty stderr for json output may need `--json-format array` added. Change those test invocations, never the warning.
- [ ] **Step 5:** Add CHANGELOG `### Changed`, then commit `feat(cli): warn when --json-format is implicit (TEG-17)`.

Ruling: the default stays `array` in this iteration. Flipping it breaks consumers who parse stdout, so it is a maintainer release decision, recorded as deferred in TASKS.md.

### Task 3: Tests for the supply-chain gate tools (T-27, TEG-17)

**Files:** create `tests/test_supply_chain_tools.py`. Modify `tools/check_sbom_lock.py` and `tools/check_dependency_exceptions.py` only if a test exposes a real bug; report any such change separately.

Both tools run in CI (`ci.yml` lines ~167 and ~179) and have 0% coverage. Load each module with `importlib.util.spec_from_file_location`, the way existing tests load other `tools/*.py` modules (grep `spec_from_file_location` in `tests/`). Drive `main()` with `monkeypatch.setattr(sys, "argv", ...)` and tmp files. Use `monkeypatch.chdir`, or patch module-level paths, where a tool reads fixed repo paths.

- [ ] **Step 1: Write the tests** for `check_sbom_lock`:
  - `test_sbom_lock_match_returns_0`: a lock with `foo==1.0` (hash lines included) and a CycloneDX SBOM with component `foo` at `1.0`.
  - `test_sbom_lock_mismatch_returns_1`: a missing or extra component, and a different version. Assert the printed names.
  - `test_sbom_lock_usage_returns_2`: wrong argument count.
  - `test_sbom_lock_normalises_names`: `Foo_Bar` against `foo-bar`.
- [ ] **Step 2: Write the tests** for `check_dependency_exceptions`. Read `main()` first, then cover the pass path and every distinct failure message it can print, one test each, named `test_dependency_exceptions_<condition>`.
- [ ] **Step 3:** Run `<venv>/bin/pytest tests/test_supply_chain_tools.py -q --cov=tools --cov-report=term-missing` (or the coverage mechanism the repo uses for `tools/`). Both modules need at least 90% line coverage; report the figure.
- [ ] **Step 4:** Commit `test: cover the SBOM-lock and dependency-exception gates (TEG-17)`.

### Task 4: `--unmapped-severity` (T-28, TEG-10)

**Files:** modify `tf_eu_guard/cli/parser.py`, `tf_eu_guard/cli/gating.py` (`apply_scan_gate`), `tf_eu_guard/config.py`, `action.yml` and the README/docs flag and input tables (wherever `--fail-on-unmapped` and `fail-on-unmapped` are documented; follow commit `e0e2887`). Tests go next to the existing gating, config and Action-input tests. CHANGELOG `### Added`.

Semantics (rulings):
- `--unmapped-severity SEVERITY` uses `type=fail_on_severity_arg`, so it is case-insensitive and `''` means "not set". The default is `None`, and the config key is `unmapped_severity`.
- When set, every **active** unmapped finding (the `unmapped` list `apply_scan_gate` already receives, which excludes inline-suppressed ones) counts as a finding of that severity for `--fail-on-severity` and for `--fail-on-any`. Reports are unchanged: unmapped findings stay unmapped and carry no severity.
- When unmapped findings trip the gate, print to stderr: `Fail: {n} unmapped Checkov finding(s) counted as {LEVEL} (--unmapped-severity) at or above threshold ({threshold or 'ANY'}).`
- The existing "Note: … do not affect this gate" line is printed only when unmapped findings exist, a gate is set, and they were not counted (option unset, or level below the threshold) and `--fail-on-unmapped` is unset.
- Without a gate (`--fail-on-severity` and `--fail-on-any` both unset), the option has no effect.
- Action: a new input `unmapped-severity` (default `''`), passed through as `--unmapped-severity "$INPUT_UNMAPPED_SEVERITY"` only when it is non-empty, mirroring `fail-on-severity`.

- [ ] **Step 1: Write the failing tests** (unit tests on `apply_scan_gate` with a `Namespace`, plus one CLI end-to-end test):
  - `test_unmapped_severity_counts_at_threshold`: `fail_on_severity="HIGH"`, `unmapped_severity="HIGH"`, one unmapped finding and no mapped ones. The function returns `EXIT_FINDINGS` and stderr has the Fail line.
  - `test_unmapped_severity_below_threshold_passes`: `MEDIUM` against `HIGH` returns `EXIT_OK` and prints the Note line.
  - `test_unmapped_severity_with_fail_on_any`: returns `EXIT_FINDINGS`.
  - `test_unmapped_severity_without_gate_is_inert`: returns `EXIT_OK`, with no Fail line.
  - `test_unmapped_severity_empty_disables`: parsing `--unmapped-severity ''` gives `None`.
  - `test_unmapped_severity_ignores_suppressed`: CLI end-to-end with a crafted `--checkov-json` (build it the way existing `--checkov-json` tests do; grep `checkov_json` in `tests/`): `summary.resource_count` 1, no `failed_checks`, and one unmapped check ID (pick one absent from every registry) under `skipped_checks`. With `--fail-on-any --unmapped-severity CRITICAL --no-config`, the exit code is 0. Add a control case with the same check under `failed_checks`: exit 1.
  - `test_config_unmapped_severity`: `unmapped_severity: high` in `.tf-eu-guard.yaml` is accepted, and an invalid value raises `ConfigError`.
  - An Action-input test mirroring the existing `fail-on-unmapped` one.
- [ ] **Step 2:** Run the tests and expect FAIL.
- [ ] **Step 3:** Implement the option per the rulings. Reuse `SEVERITIES_LOW_TO_HIGH` for the rank comparison.
- [ ] **Step 4:** Run the tests and the full suite, and expect PASS. If `check_doc_counts.py` or the Action-input docs check complain, update the docs, not the checks.
- [ ] **Step 5:** Commit `feat(cli): --unmapped-severity counts unmapped findings toward the gate (TEG-10)`.

### Task 5: Emulator and snapshot follow-ups (T-29)

**Files:** modify `tests/emulator/stack.py`, `tests/emulator/conftest.py`, `tests/test_emulator_stack.py`, `tools/check_cloud_region_tables.py` and `tests/test_cloud_region_tables.py`.

**Interfaces:**
- Produces, in `tests/emulator/stack.py`:
  - `class TerraformError(RuntimeError)`. Its message is `terraform {args} failed (exit {code}):\n{stderr tail}`, where the tail is the last 4000 characters.
  - `class EmulatorUnavailable(RuntimeError)`.
  - `require_endpoint(endpoint: str, timeout: float = 5.0) -> None`. It GETs `{endpoint}/_localstack/health` with `urllib.request` and raises `EmulatorUnavailable` on any error or a non-200 response. The message names the endpoint and says to start LocalStack as the CI service does: `docker run -d --rm -p 127.0.0.1:4566:4566 -e SERVICES=s3,sqs,dynamodb,sts,iam localstack/localstack:4.9`.

- [ ] **Step 1: Write the failing tests** in `tests/test_emulator_stack.py`. They run without LocalStack.
  - `test_terraform_failure_includes_stderr`: monkeypatch `stack.subprocess.run` to return `CompletedProcess(args, 1, stdout="", stderr="Error: boom")`. `Stack.terraform("apply")` raises `TerraformError`, and "boom" and "exit 1" are in its message.
  - `test_emulator_env_points_aws_files_at_devnull`: `emulator_env(...)` sets `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` to `os.devnull`.
  - `test_emulator_env_default_reads_os_environ`: with `monkeypatch.setenv("AWS_PROFILE", "prod")` and `setenv("KEEP_ME", "1")`, `emulator_env("eu-west-1")` drops `AWS_PROFILE` and keeps `KEEP_ME`.
  - `test_require_endpoint_unreachable`: `http://127.0.0.1:9` raises `EmulatorUnavailable`, and the message contains `localstack/localstack:4.9`.
- [ ] **Step 2: Write the failing tests** in `tests/test_cloud_region_tables.py`:
  - `test_load_snapshot_rejects_non_list`: `"eu_eea": "westeurope"` raises `ValueError`.
  - `test_load_snapshot_rejects_non_string_items`: `[1, 2]` raises `ValueError`.
  - `test_unclassified_code_in_a_table_is_drift`: covers the `find_drift` branch for a code listed as `unclassified` that is also in a table. Read `find_drift` to build the input.
- [ ] **Step 3:** Run the tests and expect FAIL.
- [ ] **Step 4: Implement.**
  - `Stack.terraform` uses `check=False` and raises `TerraformError`.
  - `emulator_env` sets both AWS file variables to `os.devnull` after the scrub.
  - In the `endpoint` fixture in `conftest.py`, call `require_endpoint` once per session and convert `EmulatorUnavailable` into `pytest.fail(str(exc))` (only reached when the tier is opted in).
  - `load_snapshot` validates `eu_eea`, `third_country` and `unclassified` as lists of strings.
- [ ] **Step 5:** Run the tests, then with LocalStack started as above run `TFEG_RUN_EMULATOR=1 <venv>/bin/pytest tests/emulator -p no:cacheprovider -o addopts="" -q`. Expect 2 passed. Stop the container afterwards.
- [ ] **Step 6:** Commit `test: surface terraform stderr, guard the emulator endpoint, validate region snapshots`.
