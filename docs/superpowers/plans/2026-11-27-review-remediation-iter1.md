# Review remediation, iteration 1, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-01 to T-06 (REVIEW.md TEG-01, TEG-02, TEG-03, TEG-06, and the TEG-05/07/11/12 doc items) on branch `version_0.10.0`.

**Architecture:** One new pure module (`tf_eu_guard/reporting/untrusted.py`) sanitises every untrusted string before it reaches a terminal or stderr. One new CLI flag (`--no-discovery`) is wired through config discovery, waiver discovery, the Python API and the Action. The changed-scope rule for `--changed-since` moves into `tf_eu_guard/changed.py` as one pure function. The image and CI task and the docs task touch no Python logic.

**Tech Stack:** Python 3.11-3.14, argparse, Rich, pytest, bash (composite Action), Docker, trivy 0.76.2, GitHub Actions.

**Spec:** `REVIEW.md` (findings TEG-01, TEG-02, TEG-03, TEG-05, TEG-06, TEG-07, TEG-11, TEG-12, including section 7) and `TASKS.md` rows T-01 to T-06.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory (outside the repo; it holds the review venv, the lab fixtures and the recheck harness).

- Work on branch `version_0.10.0` in `/home/dev/tf-eu-guard`. Push only that branch. Never create or push tags; never merge into `main`; no pull-request actions.
- Supported Python 3.11-3.14; no new runtime dependency; ruff (line length 100), `ruff format --check` and `mypy --ignore-missing-imports tf_eu_guard tools` stay clean.
- Test command: `<scratchpad>/venv/bin/pytest`, run from the repo root (that venv has the project installed in editable mode from the locks; `<venv>` below means its directory). Full-suite runs use `TFEG_RUN_CHECKOV=1`.
- Every `uses:` in workflows and `action.yml` is pinned to a 40-hex SHA with a `# vX.Y.Z` comment.
- Each task adds its own bullet under `## [Unreleased]` in `CHANGELOG.md` (subsections `### Added`, `### Changed`, `### Fixed`, `### Security` as appropriate).
- `TASKS.md` is git-ignored by project convention (`TASKS*` in .gitignore). Implementers do not edit it; the controller updates its status column after each task review.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Sanitising escapes characters; it never drops a finding or truncates a value.

## Review Focus

1. **Ordinary text stays readable:** tabs, spaces, non-ASCII letters (for example `café` or `データ`) in resource names must pass through sanitising unchanged. *Pinned by `test_sanitize_keeps_tabs_and_unicode_letters` (Task 1).*
2. **The Action re-enables workflow commands on every path:** after a container failure (exit 3) the Action's own `::error::` lines must still work, so the resume token must be echoed immediately after `docker run` whatever its exit status. *Pinned by `test_action_resumes_workflow_commands_after_failed_scan` (Task 3).*
3. **`--no-discovery` never drops explicit files:** `--config FILE` and `--waivers FILE` still apply with `--no-discovery`. *Pinned by `test_no_discovery_keeps_explicit_waivers_and_config` (Task 2).*
4. **Kubernetes `--changed-since` stays file-granular:** manifests have no cross-file semantics, so the directory widening applies to Terraform only. *Pinned by `test_changed_scope_kubernetes_is_file_granular` (Task 4).*
5. **A user's existing Action config keeps working when they opt in:** `discover-config: true` restores the 0.9 behaviour exactly (no `--no-discovery` in argv). *Pinned by `test_action_discover_config_true_omits_flag` (Task 3).*

---

### Task 1: Sanitise untrusted strings in terminal and stderr output (T-01, TEG-03)

**Files:**
- Create: `tf_eu_guard/reporting/untrusted.py`
- Modify: `tf_eu_guard/reporting/dev_report.py`, `waived.py`, `baselined.py`, `suppressed.py`, `weakening.py` (every `escape(<untrusted>)` becomes `escape(sanitize(<untrusted>))`); `tf_eu_guard/cli/pipeline.py` (the stderr prints at lines 88, 95 and 114 that interpolate waiver, check or path values); `tf_eu_guard/checkov/process.py:358` and `remote_modules_warning`
- Test: `tests/test_untrusted_output.py`

**Interfaces:**
- Produces: `sanitize(value: object) -> str` in `tf_eu_guard.reporting.untrusted`. Tasks 2-6 do not call it.

Rules for `sanitize`: `None` becomes `""`; other values go through `str()`. Replace newline with the two characters backslash-n and carriage return with backslash-r. Replace every other code point in U+0000-U+001F (except U+0009 tab), U+007F and U+0080-U+009F with backslash-x plus two lowercase hex digits. Replace U+202A-U+202E and U+2066-U+2069 with backslash-u plus four lowercase hex digits. Leave everything else unchanged. Use one precompiled regex and `re.sub` with a function.

- [ ] **Step 1: Write the failing tests** in `tests/test_untrusted_output.py` (the Python literals below are exactly what the test file contains):
  - `test_sanitize_escapes_controls`: `assert sanitize("a\nb\rc\x1b[2K\x07\x7f\x9b") == r"a\nb\rc\x1b[2K\x07\x7f\x9b"`.
  - `test_sanitize_escapes_bidi`: `assert sanitize("x\u202ey\u2066") == r"x\u202ey\u2066"`.
  - `test_sanitize_keeps_tabs_and_unicode_letters`: `assert sanitize("a\tcafé データ") == "a\tcafé データ"` and `assert sanitize(None) == ""`.
  - `test_dev_report_neutralises_workflow_commands`: build one `EnrichedFinding` whose `resource` is `"web\n::error title=X::forged\n\x1b]8;;https://evil\x1b\\"` and whose `file_path` is `"/a\n::warning::b.tf"`. Render it with `generate_dev_report`, capturing with `capsys` the way `tests/test_reporting_terminal.py` does. Assert that no output line starts with `::` after `lstrip()`, and that `"\x1b]8"` is not in the output.
  - `test_waiver_and_weakening_lines_are_sanitised`: the same two assertions for `print_weakening_to_stderr(["exclude: a\n::error::x"])`, and for the waived section with a waiver whose `owner` is `"o\n::error::x"`.
- [ ] **Step 2: Run them and confirm they fail.** Run: `pytest tests/test_untrusted_output.py -v`. Expected: ImportError for `tf_eu_guard.reporting.untrusted`.
- [ ] **Step 3: Implement `sanitize` and apply it** at every listed call site. Sanitise the values that come from the checkout or from Checkov: resource, file path, check name, check ID, suppression reason, waiver owner and reason, weakening lines, symlink paths, module names and sources. Do not sanitise fixed text written by the tool.
- [ ] **Step 4: Run the new and the existing terminal tests.** Run: `pytest tests/test_untrusted_output.py tests/test_reporting_terminal.py tests/test_suppressed.py tests/test_waivers.py tests/test_baseline.py -q`. Expected: all pass.
- [ ] **Step 5: Reproduce the lab case.** Run: `<venv>/bin/tf-eu-guard scan <scratchpad>/lab/e7-k8s --iac-type kubernetes --output dev | grep -c '^::'`. Expected: `0` (it was 18).
- [ ] **Step 6: CHANGELOG (`### Security`), commit** `fix(security): sanitise untrusted strings in terminal and stderr output (TEG-03)`.

---

### Task 2: `--no-discovery` in the CLI and the Python API (T-02, TEG-01)

**Files:**
- Modify: `tf_eu_guard/cli/parser.py` (new flag; `apply_config` at line 378), `tf_eu_guard/cli/pipeline.py` (`_waiver_path` at line 63), `tf_eu_guard/api.py` (`scan()` keyword), `docs/configuration.md`, `docs/waivers.md`, `README.md` (Basic Scan section)
- Test: `tests/test_config.py`, `tests/test_waivers.py`, `tests/test_api.py`

**Interfaces:**
- Produces: CLI flag `--no-discovery` (`store_true`, dest `no_discovery`); `scan(..., no_discovery: bool = False)` in `tf_eu_guard.api`, which appends `--no-discovery` to argv when true. Task 3 passes the flag from the Action.

Behaviour: with `--no-discovery`, `.tf-eu-guard.yaml` and `.tf-eu-guard-waivers.yaml` in the scan root are not read. `--config`, `--waivers` and a config's `waivers:` key still apply. When a discoverable file exists but is skipped, print `Note: --no-discovery: ignored <path>` to stderr (one line per file). Help text: `"Do not read .tf-eu-guard.yaml or .tf-eu-guard-waivers.yaml from the scan root (files in a pull request are controlled by its author). --config and --waivers still apply."`

- [ ] **Step 1: Write the failing tests**
  - In `tests/test_config.py`, `test_no_discovery_ignores_scan_root_config`: the scan root has a `.tf-eu-guard.yaml` with `severity_overrides: {CKV_AWS_16: INFO}`, and Checkov is stubbed to return one `CKV_AWS_16` failure (reuse that file's existing stubbing helper). With `--fail-on-severity HIGH --no-discovery` the exit code is 1 and stderr contains `Note: --no-discovery: ignored`. Without the flag the exit code is 0.
  - In `tests/test_waivers.py`, `test_no_discovery_ignores_scan_root_waivers`: the same pattern, with a `.tf-eu-guard-waivers.yaml` that waives the finding. Exit 1 with the flag; exit 0 without it.
  - In `tests/test_waivers.py`, `test_no_discovery_keeps_explicit_waivers_and_config`: an explicit `--waivers FILE` outside the scan root still waives the finding with `--no-discovery` set (exit 0).
  - In `tests/test_api.py`, `test_scan_no_discovery_keyword`: `scan(root, no_discovery=True)` leaves a discovered override unapplied (the finding keeps its registry severity).
- [ ] **Step 2: Run them and confirm they fail.** Run: `pytest tests/test_config.py tests/test_waivers.py tests/test_api.py -k no_discovery -v`. Expected: argparse error (unrecognised argument), or TypeError in the API test.
- [ ] **Step 3: Implement** the flag, the two discovery guards, the stderr notes and the API keyword. Document the flag with one short paragraph in each of the three docs files.
- [ ] **Step 4: Run.** Run: `pytest tests/test_config.py tests/test_waivers.py tests/test_api.py tests/test_cli_scan.py -q`. Expected: all pass.
- [ ] **Step 5: CHANGELOG (`### Added`), commit** `feat(cli): --no-discovery skips scan-root config and waiver files (TEG-01)`.

---

### Task 3: Action: `discover-config` input and a `stop-commands` bracket (T-03, TEG-01, TEG-03)

**Files:**
- Modify: `action.yml` (new input, `env:` entry `INPUT_DISCOVER_CONFIG`, argv construction, a bracket around `docker run`), `README.md` (the Action inputs table and the trusted-config paragraph near line 486)
- Test: `tests/test_action.py`

**Interfaces:**
- Consumes: CLI flag `--no-discovery` (Task 2).

Behaviour:
- New input `discover-config`, default `'false'`. Description: `'Read .tf-eu-guard.yaml and .tf-eu-guard-waivers.yaml from the scanned directory (true, 1 or yes, any case). Off by default because a pull request controls those files; use config or trusted-config instead'`.
- When `is_true "$INPUT_DISCOVER_CONFIG"` is false, append `--no-discovery` to `args`.
- Immediately before `docker run`: `stop_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"` and `echo "::stop-commands::$stop_token"`. Immediately after the `status=$?` line, before any other output: `echo "::$stop_token::"`.

- [ ] **Step 1: Write the failing tests** in `tests/test_action.py`. First extend `STUB_DOCKER` so that its `run` branch prints `printf '%s\n' "$STUB_STDOUT"` when `STUB_STDOUT` is set, and add `DISCOVER_CONFIG` to the empty-input list in `_run_action`.
  - `test_action_passes_no_discovery_by_default`: `"--no-discovery" in argv`.
  - `test_action_discover_config_true_omits_flag`: with `INPUT_DISCOVER_CONFIG="True"`, `"--no-discovery" not in argv`.
  - `test_action_brackets_container_output_with_stop_commands`: with `STUB_STDOUT="::error::forged"`, stdout has a line matching `^::stop-commands::[0-9a-f]{32}$` before the `::error::forged` line, and a line `::<same token>::` after it.
  - `test_action_resumes_workflow_commands_after_failed_scan`: with `STUB_EXIT=3`, the resume line is present and the step's exit code is 3.
  - Add `discover-config` to the inputs asserted by `test_action_declares_new_inputs`.
- [ ] **Step 2: Run them and confirm they fail.** Run: `pytest tests/test_action.py -k "discovery or discover_config or stop_commands or resumes" -v`. Expected: FAIL.
- [ ] **Step 3: Implement** in `action.yml`. Keep the `env:`-only input handling (so `test_action_inputs_are_passed_through_env_not_shell_code` still holds) and use no bash-4-only constructs. Document the input in the README inputs table, and add to the trusted-config paragraph that discovery is off by default since 0.10.
- [ ] **Step 4: Run.** Run: `pytest tests/test_action.py tests/test_ci_workflows.py -q`. Then run `/home/dev/.local/bin/shellcheck -s bash` on the extracted `run:` block; extract it with `python3 -I <scratchpad>/extract_run.py action.yml OUT.sh`, where `<scratchpad>` is `<scratchpad>`. Expected: all tests pass; shellcheck reports no warning or error.
- [ ] **Step 5: CHANGELOG (`### Changed`: discovery is off by default in the Action, a behaviour change; `### Security`: the stop-commands bracket), commit** `feat(action): discovery off by default and stop-commands bracket (TEG-01, TEG-03)`.

---

### Task 4: `--changed-since` widens the Terraform scope to related directories (T-04, TEG-02)

**Files:**
- Modify: `tf_eu_guard/changed.py` (new function), `tf_eu_guard/cli/pipeline.py:229` (`inside()` uses it), the `--changed-since` help string in `tf_eu_guard/cli/parser.py`, and the README `--changed-since` text
- Test: `tests/test_changed_only.py`

**Interfaces:**
- Produces: `in_changed_scope(path: Path, changed: set[Path], iac_type: str) -> bool` in `tf_eu_guard.changed`. `path` and every member of `changed` are resolved absolute paths.

Rule: if `path in changed`, return True. If `iac_type` is not `"terraform"`, return False. Otherwise, with `TF = (".tf", ".tfvars", ".hcl")`, return True if any `c` in `changed` whose name ends with a suffix in `TF` has `c.parent` equal to `path.parent`, an ancestor of `path.parent`, or a descendant of `path.parent`. Help and docs text: a changed Terraform file widens the scope to its module directory, that directory's parents and its subdirectories; sibling modules reached through `../` sources are not followed.

- [ ] **Step 1: Write the failing tests** in `tests/test_changed_only.py`:
  - `test_changed_scope_same_directory`: `in_changed_scope(root/"rds.tf", {root/"variables.tf"}, "terraform") is True`.
  - `test_changed_scope_ancestor_and_descendant`: `root/"modules/db/main.tf"` is in scope for a change to `root/"terraform.tfvars"`, and `root/"main.tf"` is in scope for a change to `root/"modules/db/variables.tf"`.
  - `test_changed_scope_unrelated_sibling_and_non_tf`: `root/"a/main.tf"` is NOT in scope for a change to `root/"b/main.tf"`, nor for a change to `root/"README.md"`.
  - `test_changed_scope_kubernetes_is_file_granular`: `in_changed_scope(root/"a.yaml", {root/"b.yaml"}, "kubernetes") is False`.
  - `test_changed_since_cross_file_change_keeps_finding`: in the `repo` fixture, commit `variables.tf` and `rds.tf` at `base`, then change only `variables.tf`. With Checkov stubbed to return one `CKV_AWS_16` failure on `/rds.tf`, `run_cli(... "--changed-since", "base", "--fail-on-severity", "HIGH")` returns 1.
  - Update `test_changed_since_filters_findings`, which needs non-Terraform files to keep its file-granular expectation. Rename its fixture files to `a.yaml` and `b.yaml` (the `repo` fixture and the stubbed paths) and run it with `--iac-type kubernetes` and `"check_type": "kubernetes"`. Keep its assertions otherwise unchanged.
- [ ] **Step 2: Run them and confirm they fail.** Run: `pytest tests/test_changed_only.py -v`. Expected: ImportError on `in_changed_scope`.
- [ ] **Step 3: Implement** `in_changed_scope` and make `inside()` call it with `args.iac_type`.
- [ ] **Step 4: Run.** Run: `pytest tests/test_changed_only.py tests/test_cli_scan.py -q`. Then reproduce the lab case: in `<scratchpad>/lab/e10-changed` run `<venv>/bin/tf-eu-guard scan . --fail-on-severity HIGH --changed-since main; echo $?`. Expected: all tests pass, and the lab scan exits `1` (it was 0).
- [ ] **Step 5: CHANGELOG (`### Fixed`), commit** `fix(cli): --changed-since keeps findings affected by changes in related Terraform files (TEG-02)`.

---

### Task 5: Refresh the base-image digest and gate the image on trivy (T-05, TEG-06)

**Files:**
- Modify: `Dockerfile:1,20`
- Create: `.trivyignore.yaml`
- Modify: `.github/workflows/ci.yml` (new job `image-scan`)
- Test: `tests/test_ci_workflows.py`

Values:
- Both `FROM` lines become `python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b` (resolved on 2026-11-27). Re-resolve with `docker pull python:3.12-slim && docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'`, and use the newer digest if it differs.
- `.trivyignore.yaml`:

```yaml
# Bounded exceptions for the image-scan job (ci.yml). Each entry needs a
# statement and an expiry; an expired entry fails the scan again.
vulnerabilities:
  - id: CVE-2026-124851
    statement: libzstd1 fix (1.5.7+dfsg-1+deb13u1) is not in the python:3.12-slim base yet; refresh the digest when it is.
    expired_at: 2027-01-31
```

- Job `image-scan` in `ci.yml`: `runs-on: ubuntu-24.04`, `timeout-minutes: 20`, `needs: [lint]`, the workflow's default read-only permissions. Steps:
  1. The same pinned `actions/checkout` as the other jobs, with `persist-credentials: false`.
  2. `docker build -t tf-eu-guard:ci .`
  3. Install trivy the way the lint job installs actionlint: env `TRIVY_VERSION: "0.76.2"`, and `TRIVY_SHA256` taken from that release's `trivy_0.76.2_checksums.txt` entry for `trivy_0.76.2_Linux-64bit.tar.gz`, checked with `sha256sum --check --strict`.
  4. `"$RUNNER_TEMP/trivy" image --ignore-unfixed --exit-code 1 --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml tf-eu-guard:ci`

- [ ] **Step 1: Write the failing tests** in `tests/test_ci_workflows.py`:
  - `test_image_scan_job_gates_on_fixable_high_and_critical`: the `image-scan` job exists, and its commands contain `--ignore-unfixed`, `--exit-code 1`, `--severity HIGH,CRITICAL`, `--ignorefile .trivyignore.yaml` and `sha256sum --check`.
  - `test_trivyignore_entries_have_statement_and_future_expiry`: every entry in `.trivyignore.yaml` has a non-empty `statement`, and an `expired_at` date in the future and at most 120 days ahead.
  - `test_dockerfile_stages_share_one_pinned_base`: exactly two `FROM` lines, equal to each other, matching `python:3\.12-slim@sha256:[0-9a-f]{64}`.
- [ ] **Step 2: Run them and confirm they fail.** Run: `pytest tests/test_ci_workflows.py -k "image_scan or trivyignore or share_one_pinned_base" -v`. Expected: the first two FAIL; the third PASSES (it is a guard).
- [ ] **Step 3: Implement** the digest, the ignore file and the job.
- [ ] **Step 4: Verify locally.**
  - Run: `pytest tests/test_ci_workflows.py tests/test_packaging.py -q`.
  - Run: `docker build -t tf-eu-guard:ci . && /home/dev/.local/bin/trivy image --skip-db-update --ignore-unfixed --exit-code 1 --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml tf-eu-guard:ci; echo exit=$?`
  - Run a smoke scan: `docker run --rm --network none -v "$PWD/examples/vulnerable-aws:/scan:ro" tf-eu-guard:ci /scan --output json --fail-on-severity HIGH >/dev/null; echo exit=$?`
  - Run the workflow linter: `<scratchpad>/plan-check/ci-tools-new/bin/zizmor --offline --persona auditor --min-severity informational .`
  - Expected: tests pass; trivy `exit=0`; smoke `exit=1`; zizmor reports no findings.
- [ ] **Step 5: CHANGELOG (`### Security`), commit** `build: refresh python:3.12-slim digest and gate the image on trivy (TEG-06)`.

---

### Task 6: Documentation corrections (T-06; TEG-07, TEG-11 typos, TEG-12, TEG-05 scope)

**Files:**
- Modify: `SECURITY.md:46`, `docs/limitations.md:65,166`, `tf_eu_guard/mapping/registry-aws.yaml:337,1777,2724`, `tf_eu_guard/mapping/registry-kubernetes.yaml:110`, `README.md` (the "What It Does" item 5)
- Test: `tests/test_docs_accuracy.py`

Exact text:
- SECURITY.md: replace "Scanned code is only read, never executed, and remote Terraform modules are not downloaded." with "Scanned code is never run as a program, but Checkov evaluates Terraform expressions from it in a restricted interpreter (asteval), and remote Terraform modules are not downloaded unless --download-external-modules is given. Scan untrusted code, such as pull requests from forks, in the container image or the GitHub Action, which runs it without network access, with a read-only filesystem and with all capabilities dropped."
- docs/limitations.md:65: replace "(there is no `--var-file` support)" with "(pass non-default variable files with `--var-file`; `terraform.tfvars` and `*.auto.tfvars` are loaded automatically)".
- docs/limitations.md:166: the sentence becomes "Variables set only in a `.tfvars` file other than `terraform.tfvars` or `*.auto.tfvars` are unresolved unless the file is passed with `--var-file FILE`."
- Registry: "weakensing" becomes "weakening" (4 places).
- README "What It Does" item 5: add "(AWS only; Azure and GCP locations are not evaluated)" after "configurable region residency policy".

- [ ] **Step 1: Write the failing test** `test_docs_do_not_repeat_corrected_claims` in `tests/test_docs_accuracy.py`:
  - `"never executed"` is not in SECURITY.md.
  - The substring `"no ` + backtick + `--var-file` + backtick + ` support"` is not in docs/limitations.md.
  - `"weakensing"` is in no `tf_eu_guard/mapping/registry-*.yaml`.
  - `"AWS only"` is in README.md.
- [ ] **Step 2: Run it and confirm it fails.**
- [ ] **Step 3: Apply the exact text above.**
- [ ] **Step 4: Run.** Run: `pytest tests/test_docs_accuracy.py tests/test_doc_counts.py tests/test_registry.py tests/test_registry_validation.py tests/test_markdown_style.py -q` and `<venv>/bin/python tools/check_doc_counts.py`. Expected: all pass.
- [ ] **Step 5: CHANGELOG (`### Fixed`, documentation), commit** `docs: correct execution, var-file and residency-scope claims; fix registry typos`.

---

### Iteration close (controller, after the final whole-branch review)

- [ ] Run the full gate: `ruff check . && ruff format --check . && mypy --ignore-missing-imports tf_eu_guard tools && TFEG_RUN_CHECKOV=1 pytest -q`. Expected: 0 failures.
- [ ] Rebuild the image and rerun `<scratchpad>/recheck.sh tf-eu-guard:ci`, once with the harness as it is and once with `--no-discovery` added to the TEG-01 rows. Expected: TEG-02, TEG-03 and TEG-12 report NOT REPRODUCED. TEG-01 reports NOT REPRODUCED when `--no-discovery` is given (the Action's new default), and the remaining findings report as before. Record the table in REVIEW.md section 7 under "After iteration 1".
- [ ] `git push origin version_0.10.0` (no tags).
