# Review remediation, iteration 2, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-07 to T-12 (REVIEW.md TEG-01 waiver bounds, TEG-04, TEG-05 warnings, TEG-09, TEG-13, TEG-15) on branch `version_0.10.0`.

**Architecture:** Three CLI changes, each a small pure function plus its call site: waiver bounds in `waivers.py`; a strict `--checkov-json` mode under gates in `checkov/json.py`; residency-blind-spot warnings in `residency.py` and `checkov/process.py`. Then three changes to `action.yml`: a commit fallback in provenance, workspace validation of the `path` and `checkov-json` inputs, and image attestation verification. The three Action tasks edit one file, so they run in sequence.

**Tech Stack:** Python 3.11-3.14, argparse, pytest, bash (composite Action), Docker, the `gh` CLI (`gh attestation verify`).

**Spec:** `REVIEW.md` (TEG-01, TEG-04, TEG-05, TEG-09, TEG-13, TEG-15; section 7 shows these were still reproducing on the post-iteration-1 image) and `TASKS.md` rows T-07 to T-12.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory (outside the repo; it holds the review venv, the lab fixtures and the recheck harness).

- Branch `version_0.10.0` in `/home/dev/tf-eu-guard`. Never create or push tags, never merge into `main`, take no pull-request actions, and do not push (the controller pushes). Never rewrite history: no `filter-branch`, no rebase, no amending a commit you did not create in this task. Never `git checkout`, `restore` or revert a file you did not change in this task.
- Supported Python 3.11-3.14; no new runtime dependency; ruff, `ruff format --check` (on tracked files: `git ls-files '*.py' '*.md' | xargs ruff format --check`) and `mypy --ignore-missing-imports tf_eu_guard tools` stay clean.
- `<venv>` is `<scratchpad>/venv` (pytest, ruff, mypy, tf-eu-guard). Full-suite runs use `TFEG_RUN_CHECKOV=1`.
- Every `uses:` is pinned to a 40-hex SHA with a `# vX.Y.Z` comment. Action inputs reach the script only through `env:`, never through `${{ }}` in `run:`. No bash-4-only constructs.
- Untrusted strings printed to a terminal or stderr go through `tf_eu_guard.reporting.untrusted.sanitize`.
- Each task adds its bullet under `## [Unreleased]` in `CHANGELOG.md` in the existing subsections (no duplicate headings). Do not edit `REVIEW.md`, `TASKS.md` or `docs/superpowers/`.
- Commit messages end with `Co-Authored-By: Claude <Model> 5.5 <noreply@anthropic.com>`, naming the model that wrote the commit.
- New CLI behaviour that changes exit codes is opt-in unless the task says otherwise.

## Review Focus

1. **Existing waiver files keep working:** without `max_waiver_days`, a far-future waiver still applies (backward compatibility). *Pinned by `test_long_waiver_applies_without_limit` (Task 1).*
2. **`--checkov-json` without a gate is unchanged:** it only warns, it never exits 3. *Pinned by `test_checkov_json_without_gate_only_warns` (Task 2).*
3. **No warning noise on ordinary repositories:** `.git`, `.github` and `.terraform` never trigger the hidden-directory warning. *Pinned by `test_hidden_dir_warning_ignores_tooling_dirs` (Task 3).*
4. **A malformed `TF_EU_GUARD_COMMIT` is never recorded.** *Pinned by `test_commit_env_must_be_hex` (Task 4).*
5. **Verification failure never blocks the scan:** it falls back to a local build (the 0.9 behaviour), and an explicit `image` input is untouched. *Pinned by `test_action_unverified_image_falls_back_to_local_build` and `test_action_explicit_image_skips_verification` (Task 6).*

---

### Task 1: Waiver bounds (T-07, TEG-01)

**Files:** `tf_eu_guard/waivers.py`, `tf_eu_guard/cli/pipeline.py` (`_apply_waiver_file`), `tf_eu_guard/cli/parser.py`, `tf_eu_guard/config.py`, `tf_eu_guard/api.py`, `action.yml` (new input), `docs/waivers.md`, `docs/configuration.md`, `README.md`. Test: `tests/test_waivers.py`, `tests/test_config.py`, `tests/test_action.py`.

**Interfaces:**
- `apply_waivers(findings, waivers, today, max_days: int | None = None) -> WaiverResult`. `WaiverResult` gains `too_long: list[Waiver]`: waivers that matched a finding but expire after `today + timedelta(days=max_days)`. They are not applied, so their findings stay active.
- CLI `--max-waiver-days N` (int, at least 1, dest `max_waiver_days`); config key `max_waiver_days` (int, at least 1); API keyword `max_waiver_days: int | None = None`; Action input `max-waiver-days` (default `''`, passed as `--max-waiver-days` when non-empty, and must match `^[0-9]+$` or the step exits 2 with `::error::`).
- Stderr messages, with sanitised values:
  - `Warning: waiver for <check_id> <resource> expires <YYYY-MM-DD>, more than <N> days ahead (--max-waiver-days); not applied`
  - At load, once per waiver without `file`: `Warning: waiver for <check_id> <resource> has no file pattern; it matches that resource in every file`

- [ ] Tests:
  - `test_waiver_beyond_max_days_is_not_applied`: expires today+400, `max_days=365`, so the finding stays active and the waiver is listed in `too_long`.
  - `test_waiver_within_max_days_applies`.
  - `test_long_waiver_applies_without_limit`.
  - `test_cli_max_waiver_days_trips_gate`: E2-style setup, `--fail-on-severity HIGH --max-waiver-days 90`, a waiver expiring 9999-12-31; exit 1 and the warning on stderr.
  - `test_config_max_waiver_days`: valid value accepted; `0`, `"x"` and `true` exit 2.
  - `test_waiver_without_file_warns`.
  - `test_action_passes_max_waiver_days` and `test_action_rejects_non_numeric_max_waiver_days`.
- [ ] RED, implement, GREEN; full gate; CHANGELOG (`### Added`); commit `feat(waivers): --max-waiver-days and a warning for waivers without a file pattern (TEG-01)`.

---

### Task 2: Strict `--checkov-json` when a gate is set (T-10, TEG-09)

**Files:** `tf_eu_guard/checkov/json.py` (`load_checkov_json`, `_warn_missing_custom_checks`), `tf_eu_guard/cli/pipeline.py` (the `load_checkov_json` call), README (the "Limits of pre-generated JSON" list). Test: `tests/test_checkov_json_guards.py`.

**Interfaces:**
- `load_checkov_json(json_source, iac_type="terraform", extra_check_types=(), require_complete: bool = False)`.
- With `require_complete=True`, and outside `allow_partial_results(True)`, raise `CheckovRuntimeError` (exit 3) when:
  - (a) no `EUGUARD_*` check appears in the passed, failed or skipped lists. Message: `"the Checkov JSON contains no EUGUARD_* check, so the tf-eu-guard custom checks were not run; a gated scan cannot trust it. Regenerate it with --external-checks-dir <dir>, or pass --allow-partial"`.
  - (b) `summary.resource_count` is the int `0`. Message: `"the Checkov JSON reports 0 resources scanned; a gated scan cannot trust it. Pass --allow-partial to accept it"`.
- Inside `allow_partial_results(True)`, or when `require_complete=False`, both conditions are warnings. Condition (b) is a new warning `"Warning: the Checkov JSON reports 0 resources scanned"`.
- The pipeline passes `require_complete=bool(fail_on_severity or fail_on_any or fail_on_suppressed or fail_on_unmapped)`.

- [ ] Tests:
  - `test_checkov_json_gate_without_custom_checks_exits_3` (the forged file from REVIEW.md E13, with `--fail-on-severity LOW`).
  - `test_checkov_json_gate_zero_resources_exits_3`.
  - `test_checkov_json_gate_allow_partial_warns` (exit 0, warning on stderr).
  - `test_checkov_json_without_gate_only_warns`.
  - `test_checkov_json_gate_complete_input_passes`, using an existing fixture that contains EUGUARD checks.
- [ ] RED, implement, GREEN; full gate; CHANGELOG (`### Changed`, gated behaviour change); commit `feat(cli): a gated --checkov-json scan fails closed on incomplete input (TEG-09)`.

---

### Task 3: Residency blind-spot warnings (T-09, TEG-05)

**Files:** `tf_eu_guard/residency.py` (new function), `tf_eu_guard/checkov/process.py` (new function, called in `run_checkov` next to the remote-modules warning), `tf_eu_guard/cli/pipeline.py` (calls the residency warning for `iac_type == "terraform"`, for both live and `--checkov-json` input), `docs/limitations.md`. Test: `tests/test_residency.py`, `tests/test_checkov_process.py`.

**Interfaces:**
- `aws_region_unset_warning(checkov_output: dict[str, Any]) -> str | None`. It returns a message when some `resource` in the passed, failed or skipped results matches `(^|\.)aws_[a-z0-9_]+\.` and no result has `check_id == "EUGUARD_POLICY_001"`. Message: `Warning: AWS resources were scanned but no provider "aws" block sets a region, so the residency checks cannot tell where they deploy (the region comes from the environment at apply time). Scan a Terraform plan (--iac-type terraform_plan) to check the real region.`
- `hidden_source_dirs(root: Path, iac_type: str, excludes: Sequence[str] = ()) -> list[Path]`. It returns the top-most directories under `root` whose name starts with `.`, that are not in `{".git", ".github", ".gitlab", ".terraform", ".venv", ".tox", ".cache"}`, are not matched by `--exclude`, and contain at least one file with a suffix from `SOURCE_SUFFIXES[iac_type]` at any depth. They are sorted, and symlinks are not followed. Warning: `Warning: not scanned: <n> hidden director(y|ies) contain <suffixes> files that Checkov skips: <up to 5 sanitised paths>[, ... and <k> more]. Pass such a directory as the scan path to scan it.` It applies to the `terraform` and `kubernetes` directory scans only.

- [ ] Tests:
  - `test_aws_region_unset_warning_fires_without_provider_result`.
  - `test_aws_region_unset_warning_silent_when_policy_001_ran` (passed or failed).
  - `test_aws_region_unset_warning_silent_without_aws_resources`.
  - `test_hidden_source_dirs_finds_dot_prod` (REVIEW.md E9 layout).
  - `test_hidden_dir_warning_ignores_tooling_dirs`.
  - `test_hidden_source_dirs_honours_exclude`.
  - `test_hidden_source_dirs_kubernetes_yaml`.
- [ ] RED, implement, GREEN; lab check: `<venv>/bin/tf-eu-guard scan <scratchpad>/lab/e5a-noprovider` and `.../lab/e9-hidden` each print their warning on stderr; full gate; CHANGELOG (`### Added`); commit `feat(residency): warn when no AWS provider region is set or source files sit in hidden directories (TEG-05)`.

---

### Task 4: `provenance.commit` from the Action (T-11, TEG-13)

**Files:** `tf_eu_guard/provenance.py` (`build_provenance`), `tf_eu_guard/schemas/report.schema.json` (if it restricts provenance keys), `action.yml` (`docker run` gets `-e TF_EU_GUARD_COMMIT="$GITHUB_SHA"`, and `GITHUB_SHA` goes into the step `env:` only if the runner does not already provide it), README provenance paragraph (replace "is null in the Action"). Test: `tests/test_provenance.py`, `tests/test_action.py`.

**Interfaces:**
- In `build_provenance`: `commit = git_commit(args.path)` when `args.path` is set. If that is `None` and the environment variable `TF_EU_GUARD_COMMIT` matches `^[0-9a-f]{40}([0-9a-f]{24})?$`, use it. New key `"commit_source"` is `"git"`, `"environment"` or `None`.
- A `--checkov-json` run still records `commit: null`; `test_checkov_json_run_records_no_commit` stays green.

- [ ] Tests:
  - `test_commit_falls_back_to_env` (outside a repo, env set, so source is environment).
  - `test_commit_prefers_git_over_env`.
  - `test_commit_env_must_be_hex` (`"abc"` and a 40-character value with an uppercase or non-hex character are both ignored).
  - `test_action_passes_commit_env_to_container`.
  - Schema validation of the JSON object still passes.
- [ ] RED, implement, GREEN; full gate; CHANGELOG (`### Added`); commit `feat(provenance): record the CI commit when git is unavailable (TEG-13)`.

---

### Task 5: Validate the Action `path` and `checkov-json` inputs (T-12, TEG-15)

**Files:** `action.yml` (argv construction near `args+=(--checkov-json ...)` / `args+=("$INPUT_PATH")`), the README inputs table. Test: `tests/test_action.py`.

**Interfaces:** both values go through the existing `ws_rel` helper, exactly like `config`, `waivers` and `baseline`. A path with `..`, or an absolute path outside `$GITHUB_WORKSPACE`, exits 2 with the existing `::error::` message. The default `./terraform` becomes `$GITHUB_WORKSPACE/terraform` in argv.

- [ ] Tests: `test_action_rejects_dotdot_path`, `test_action_rejects_outside_checkov_json`, `test_action_path_is_workspace_absolute`. Update any existing assertion that expects the literal `./terraform` in argv; say which ones in the report.
- [ ] RED, implement, GREEN; shellcheck on the extracted run block (`python3 -I <scratchpad>/extract_run.py action.yml OUT.sh`; only the old SC2129 notes may remain); full gate; CHANGELOG (`### Security`); commit `fix(action): validate the path and checkov-json inputs like the other workspace paths (TEG-15)`.

---

### Task 6: Verify the published image's build attestation (T-08, TEG-04)

**Files:** `action.yml` (image selection block, new input `verify-image`, step `env: ACTION_TOKEN: ${{ github.token }}`), README (Action image paragraph). Test: `tests/test_action.py` (extend `STUB_DOCKER` for `pull`, `image inspect` and `build`, and add a stub `gh` that exits `$STUB_GH_EXIT` and logs its argv).

Behaviour, when `INPUT_IMAGE` is empty and `ACTION_REF` is non-empty:
1. `docker pull --quiet "$candidate"` (unchanged).
2. `ref="$(docker image inspect --format '{{index .RepoDigests 0}}' "$candidate")"`. It must match `ghcr.io/44aayush/tf-eu-guard@sha256:[0-9a-f]{64}`.
3. Unless `verify-image` is false (`is_true` semantics; default `'true'`): require `command -v gh` and `GH_TOKEN="$ACTION_TOKEN" gh attestation verify "oci://$ref" --repo 44aayush/tf-eu-guard --signer-workflow 44aayush/tf-eu-guard/.github/workflows/publish.yml >/dev/null`.
4. On success use `image="$ref"` (run by digest). On any failure (pull, inspect, digest shape, missing gh, verify) print `::notice::could not verify the published image <candidate>; building the image locally` and fall back to the existing local build.
5. An explicit `image` input skips verification (unchanged behaviour; the README already recommends pinning it by digest).

- [ ] Tests:
  - `test_action_verified_image_runs_by_digest` (docker run argv uses the `@sha256:` ref; gh argv contains `--signer-workflow`).
  - `test_action_unverified_image_falls_back_to_local_build` (gh exits 1, so a build happens and the notice is printed).
  - `test_action_missing_gh_falls_back`.
  - `test_action_verify_image_false_uses_tag`.
  - `test_action_explicit_image_skips_verification`.
  - `test_action_bad_digest_shape_falls_back`.
- [ ] RED, implement, GREEN; shellcheck; full gate; CHANGELOG (`### Security`); commit `feat(action): verify the published image's build attestation and run it by digest (TEG-04)`.

---

### Iteration close (controller)

- [ ] Final whole-branch review (Opus), one fix wave if needed, scoped re-review.
- [ ] Gate (Haiku): ruff, format, mypy, `TFEG_RUN_CHECKOV=1` pytest, `docker build --no-cache`, trivy, `recheck.sh` plus `recheck-extra.sh` extended with T-07 to T-12 rows.
- [ ] REVIEW.md section 7 "After iteration 2"; TASKS.md statuses; `git push origin version_0.10.0` (no tags).
