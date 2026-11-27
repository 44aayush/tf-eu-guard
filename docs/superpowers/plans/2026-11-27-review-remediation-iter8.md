# Review remediation, iteration 8, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-34 to T-36 on `version_0.10.0`: machine outputs for baselined unmapped findings, a registry-backed "no AWS provider region" finding (TEG-05 recommendation 1), and hardening of the coverage table and report goldens.

**Architecture:**
- Task 1 extends the counts file, the Markdown summary and the Action outputs.
- Task 2 adds `EUGUARD_POLICY_005`. It is a Checkov-shaped failed-check dict that `tf_eu_guard/residency.py` builds in the same situation where the AWS stderr warning fires today. The pipeline injects it before the mapped/unmapped split, so enrichment, waivers, baselines, `--framework`, `--skip-check` and every report treat it like any other finding.
- Task 3 hardens `tools/generate_checkov_coverage.py` and adds a second golden input to `tests/test_report_context.py`.

**Tech Stack:** Python 3.11-3.14, pytest, YAML registries, GitHub Actions.

**Spec:** REVIEW.md TEG-05 recommendation 1 ("Add a policy check: AWS resources present but no provider block sets a region. Report it as MEDIUM and fail-closed"), TEG-10, TEG-17, and section 7 "After iteration 7". TASKS.md T-34 to T-36.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is the review venv. Never write a scratchpad absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- The gate stays clean after your last change: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, `mypy --ignore-missing-imports tf_eu_guard tools`, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, `tools/generate_checkov_coverage.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1`.
- Report goldens live in `tests/fixtures/report-golden/` (regenerate with `TFEG_UPDATE_GOLDEN=1`). Regenerate only the goldens your change affects, and list in your report each changed golden file with a one-line description of the difference.
- Every user-visible change gets a CHANGELOG entry in the unreleased section.
- Registry text stays hedged. A policy finding is a project-policy deviation, not a legal conclusion.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **A plan scan never gets the new finding:** in a plan, every AWS resource carries a computed region, so `EUGUARD_POLICY_005` must not fire on `terraform_plan` input. *Pinned by `test_no_region_finding_absent_in_plan_mode` (Task 2).*
2. **An aliased provider block is enough:** a configuration whose only `provider "aws"` block has an alias and a region gets no finding. *Pinned by `test_no_region_finding_absent_with_aliased_provider` (Task 2).*
3. **The finding can be waived and baselined:** a waiver entry by check ID and file suppresses it, and a baseline from the same scan matches it. *Pinned by `test_no_region_finding_waivable_and_baselined` (Task 2).*
4. **The Action's existing outputs keep their meaning:** `baselined` stays the mapped count. *Pinned by `test_action_baselined_output_unchanged` (Task 1).*
5. **A typo in the triage file is caught:** an ID in `intentionally_unmapped` or `known_stale` that the catalogue does not contain fails `--check`. *Pinned by `test_triage_id_absent_from_catalogue_fails` (Task 3).*

---

### Task 1: Machine outputs for baselined unmapped findings (T-34)

**Files:**
- Modify `tf_eu_guard/reporting/markdown_report.py` (`render_summary` ~line 74, `render_counts` ~line 79-87), `action.yml` (outputs, and the step that reads the counts file), the auditor wording in `tf_eu_guard/reporting/auditor_report.py` (~lines 285 and 310-317) and the README Action-output table.
- Two CHANGELOG fixes: the older bullet at `CHANGELOG.md` ~85-86 reads as absolute about `"new"`; reword it to point at the array-baseline exception.
- Tests: the existing markdown/counts tests, `tests/test_action.py`, the auditor tests, and `tests/test_sarif_report.py`.

Rulings:
- The counts file gains one line, `baselined_unmapped={n}`, after `baselined=`. The existing keys and their meaning are unchanged.
- The Markdown summary line becomes `… Waived: {w} | Baselined: {b} | Baselined unmapped: {bu}`.
- The Action gains an output `baselined-unmapped` (description `'Number of baselined unmapped findings (baselined_unmapped)'`), read from the counts file the way `baselined` is.
- Auditor report: when known unmapped findings exist and `--show-unmapped` is off, the text says they are counted, not listed, and names `--show-unmapped`. The sentence "every failed check that maps to a compliance control" stays only where it is true.

- [ ] **Step 1: Write the failing tests:**
  - `test_counts_include_baselined_unmapped`
  - `test_markdown_summary_shows_baselined_unmapped`
  - `test_action_exposes_baselined_unmapped_output` (mirror the existing output tests)
  - `test_action_baselined_output_unchanged` (`baselined` equals the mapped count when both groups are non-empty)
  - `test_auditor_counts_known_unmapped_without_show_unmapped`
  - `test_build_sarif_array_baseline_omits_new_state`: a direct `build_sarif(..., baseline_covers_unmapped=False)` unit test; an unmatched unmapped result has no `baselineState`, and a matched one has `"unchanged"`.
- [ ] **Step 2:** Run them and expect FAIL.
- [ ] **Step 3:** Implement the rulings.
- [ ] **Step 4:** Run the tests and the full gate, and expect PASS. Regenerate the markdown golden if it changes.
- [ ] **Step 5:** Commit `feat(report): count baselined unmapped findings in machine outputs (TEG-10)`.

### Task 2: Registry-backed "no AWS provider region" finding (T-36, TEG-05)

**Files:**
- Modify `tf_eu_guard/residency.py` (next to `aws_region_unset_warning`, ~line 137), `tf_eu_guard/cli/pipeline.py` (~line 219, where the region warnings run) and `tf_eu_guard/mapping/registry-aws.yaml` (a new entry after `EUGUARD_POLICY_002`, plus the header comment list ~lines 860-868).
- Docs with registry counts: run `tools/check_doc_counts.py` and fix every count it names, including the severity distribution in `docs/check-mapping-table.md`. Regenerate `docs/regulatory-coverage.md` with `tools/generate_coverage_doc.py`. Also update README (residency section), `docs/limitations.md` (the missing-region case) and `docs/severity-rubric.md` if it lists residency checks.
- Tests: create `tests/test_region_unset_finding.py`.
- CHANGELOG `### Changed`: source scans of AWS stacks with no provider region now report one MEDIUM finding. The Action's default gate (HIGH) is unaffected, while `--fail-on-severity MEDIUM` or `LOW` and `--fail-on-any` now fail.

**Interfaces:**
- Produces `aws_region_unset_finding(checkov_output: dict[str, Any], *, custom_checks_loaded: bool = False) -> dict[str, Any] | None` in `tf_eu_guard/residency.py`. It returns a failed-check dict in the shape Checkov puts in `results.failed_checks` (copy the keys of a real Checkov failed check: `check_id`, `check_name`, `check_result`, `resource`, `file_path`, `file_abs_path` if present, `file_line_range`, and whatever else the parser needs). It returns it exactly when `aws_region_unset_warning` with the same arguments returns a message, and `None` otherwise. Implement both on one shared predicate so they cannot disagree.
  - `check_id`: `"EUGUARD_POLICY_005"`
  - `resource`: `"provider.aws"`
  - `file_path` and `file_line_range`: those of the first AWS resource in the scan, by sorted `(file_path, line)`.

Rulings:
- Severity is MEDIUM, as the spec requires. The single article is `framework: POLICY`, `article: "Policy RESIDENCY-001"`, `title: "Region residency policy"`, the same as `EUGUARD_POLICY_001`. It cites no GDPR or NIS2 article.
- `check_name`: `"Ensure an AWS provider block sets a region"`. The risk text, hedged, says the region comes from the environment at apply time, so the residency checks cannot tell where resources deploy. The remediation pins `provider "aws" { region = "eu-central-1" }`, or scans a plan (`--iac-type terraform_plan`) for the authoritative region.
- Inject the finding once per scan into the Checkov output's failed checks, before the mapped/unmapped split. Do not inject when `EUGUARD_POLICY_005` is excluded by `--skip-check`, or not selected by `--check` (find how the pipeline reads those args).
- Never inject for `terraform_plan` input, or for any `iac_type` other than Terraform source. Respect the existing `custom_checks_loaded` semantics for `--checkov-json`.
- The existing stderr warning stays: it carries the plan-mode hint in CI logs.
- The GCP warning is unchanged and out of scope.
- The registry entry is a custom check documented in the header comment. `tools/generate_checkov_coverage.py` ignores `EUGUARD_` IDs; confirm this.

- [ ] **Step 1: Write the failing tests:**
  - `test_no_region_finding_on_source_scan`: a CLI scan of a tmp Terraform dir with `terraform { required_providers { aws = { source = "hashicorp/aws" } } }` and one `aws_s3_bucket`, using `--no-config --output json --json-format object`. Exactly one finding has `check_id == "EUGUARD_POLICY_005"`, `severity == "MEDIUM"` and `resource == "provider.aws"`, and `--fail-on-severity MEDIUM` exits 1. This needs Checkov: mark it the way other live-scan tests are marked.
  - `test_no_region_finding_absent_with_region`
  - `test_no_region_finding_absent_with_aliased_provider`
  - `test_no_region_finding_absent_in_plan_mode`: reuse a plan fixture if one exists, otherwise a unit test on `aws_region_unset_finding` with plan-mode input.
  - `test_no_region_finding_matches_warning`: a parametrised unit test over the inputs `tests/` already uses for `aws_region_unset_warning`, asserting the finding is non-`None` iff the warning is.
  - `test_no_region_finding_respects_skip_check`
  - `test_no_region_finding_waivable_and_baselined`
- [ ] **Step 2:** Run them and expect FAIL.
- [ ] **Step 3: Implement.** Then fix the doc counts, regenerate the coverage doc, and update the affected goldens and fixtures: `examples/end2end/EXPECTED_FINDINGS.md` and the smoke baselines in `tools/smoke_baselines.json`, only if a stack there lacks a provider region (check, and say which).
- [ ] **Step 4:** Run the tests and the full gate, and expect PASS.
- [ ] **Step 5:** Commit `feat(residency): report AWS stacks with no provider region as EUGUARD_POLICY_005 (TEG-05)`.

### Task 3: Coverage-table and golden hardening (T-35)

**Files:** modify `tools/generate_checkov_coverage.py`, `tests/test_checkov_coverage.py` and `tests/test_report_context.py`. Create a second golden input fixture under `tests/fixtures/` and its goldens under `tests/fixtures/report-golden/`.

- [ ] **Step 1: Coverage tool tests (failing first):**
  - `test_triage_id_absent_from_catalogue_fails`: an `intentionally_unmapped` ID and a `known_stale` ID that are not in the catalogue each appear in `problems()`. `known_stale` for an ID that is still in the registry and absent from the catalogue stays allowed.
  - `test_load_triage_rejects_unknown_key`
  - `test_check_reports_stale_doc`: `--check` against a doc file with one changed line exits 1 and names the file. Point the tool's doc path at `tmp_path` via a module constant or an argument.
- [ ] **Step 2:** Implement. Fix the docstring's "roughly 2,000" to describe the count without a hard-coded number.
- [ ] **Step 3: Second golden input.** Build a `--checkov-json` fixture with at least 3 mapped failures, 2 unmapped failures, 1 inline-suppressed mapped finding, 1 inline-suppressed unmapped finding, and a passed `EUGUARD_POLICY_001` result, so no region warning fires. Add a parametrised golden scenario set over every `--output` format for:
  - (a) this input with `--show-unmapped`;
  - (b) this input with `--baseline` set to an object baseline (committed as a fixture) that contains one mapped and one unmapped finding of it.
  Generate the goldens from the current code and check by reading them that scenario (b) shows baselined mapped and baselined unmapped findings as known in every format.
- [ ] **Step 4:** Run the full gate. Commit `test: harden the coverage table and add baseline/unmapped report goldens (TEG-17)`.
