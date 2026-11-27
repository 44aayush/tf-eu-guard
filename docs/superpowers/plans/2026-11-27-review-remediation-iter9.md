# Review remediation, iteration 9, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-37 to T-40 on `version_0.10.0`:
- a GCP counterpart of `EUGUARD_POLICY_005`;
- a pinned plan-mode test for Azure/GCP residency;
- a release workflow that scans exactly the bytes it publishes;
- small deferred cleanups.

**Architecture:**
- Task 1 reuses the `EUGUARD_POLICY_005` machinery in `tf_eu_guard/residency.py` and `cli/pipeline.py` for `google_*` resources.
- Task 2 is a test plus a doc note.
- Task 3 changes the `image` job in `.github/workflows/publish.yml` to build once, push by digest without a tag, scan that digest, and only then add the release tag and the attestation.
- Task 4 makes small edits.

**Tech Stack:** Python 3.11-3.14, pytest, YAML registries, GitHub Actions (docker/build-push-action, docker buildx imagetools, trivy, actions/attest-build-provenance).

**Spec:** REVIEW.md TEG-05 (recommendations 1 and 2), TEG-06/TEG-04 (release image), and section 7 "After iteration 8". TASKS.md T-37 to T-40.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is the review venv. Never write a scratchpad absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- The gate stays clean after your last change: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, `mypy --ignore-missing-imports tf_eu_guard tools`, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, `tools/generate_checkov_coverage.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1`.
- Report goldens live in `tests/fixtures/report-golden/` (regenerate with `TFEG_UPDATE_GOLDEN=1`). Regenerate only affected goldens and list each changed file with its difference.
- Every user-visible change gets a CHANGELOG entry in the unreleased section.
- Registry text stays hedged. A policy finding is a project-policy deviation, not a legal conclusion.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **GCP resources that carry their own location:** a stack whose only `google_*` resources set `location` or `region` literally gets no `EUGUARD_POLICY_006`. *Pinned by `test_gcp_no_region_finding_absent_when_resources_set_location` (Task 1).*
2. **Cross-cloud stacks:** an AWS-and-GCP stack with no regions anywhere gets both 005 and 006, once each. *Pinned by `test_both_no_region_findings_once_each` (Task 1).*
3. **A failed scan never publishes a tag:** when trivy fails, no step after it adds the release tag or creates the attestation. *Pinned by `test_publish_tags_only_after_scan` (Task 3).*
4. **The scanned bytes are the published bytes:** the scan and the tag step both reference the same `steps.<build>.outputs.digest`. *Pinned by `test_publish_scans_and_tags_same_digest` (Task 3).*
5. **Azure `location = "global"` in plan mode** fails `EUGUARD_POLICY_003`, the same as in source mode. *Pinned by `test_plan_mode_azure_global_location` (Task 2).*

---

### Task 1: GCP no-region finding (T-37, TEG-05)

**Files:**
- Modify `tf_eu_guard/residency.py` (next to `gcp_region_unset_warning` and `aws_region_unset_finding`), `tf_eu_guard/cli/pipeline.py` (where `EUGUARD_POLICY_005` is injected) and `tf_eu_guard/mapping/registry-gcp.yaml` (a new entry after `EUGUARD_POLICY_004`, with the header comment if the file has one).
- Docs and counts: `tools/check_doc_counts.py` names them. Also README (next to the `EUGUARD_POLICY_005` paragraph), `docs/limitations.md` (the GCP section and the 005 notes) and `docs/check-mapping-table.md` or the GCP equivalent, if GCP checks are listed there.
- Tests: extend `tests/test_region_unset_finding.py`.
- CHANGELOG `### Changed`, with the gate effect worded like the 005 entry.

**Interfaces:**
- Produces `gcp_region_unset_finding(checkov_output: dict[str, Any], *, custom_checks_loaded: bool = False) -> dict[str, Any] | None`. It returns a non-`None` value exactly when `gcp_region_unset_warning` returns a message, sharing the same predicate.
  - `check_id`: `"EUGUARD_POLICY_006"`
  - `resource`: `"provider.google"`
  - `check_name`: `"Ensure a Google provider block or the resource sets a region or location"`
  - Anchor: the first root-module `google_*` resource, using the same `_location_key` ordering as 005.
- Registry entry: MEDIUM, with a single article `framework: POLICY`, `article: "Policy RESIDENCY-001"`, `title: "Region residency policy"`. The hedged risk text mirrors 005, and the remediation pins `provider "google" { region = "europe-west3" }` or scans a plan. The waiver advice for module repos is the same as 005's.
- Injection uses the same rules as 005: Terraform source only, one per scan, the stderr warning stays.
- Refactor the two injectors into one loop over `(finding_fn, warning_fn)` pairs, so AWS and GCP cannot drift.

- [ ] **Step 1: Write the failing tests:**
  - `test_gcp_no_region_finding_matches_warning`: parametrised over the same inputs as `gcp_region_unset_warning`'s existing tests.
  - `test_gcp_no_region_finding_injected`: monkeypatched `run_checkov` with `google_*` resources, a passed `EUGUARD_GDPR_005` result and no `EUGUARD_POLICY_004` result. Exactly one 006 finding.
  - `test_gcp_no_region_finding_absent_when_resources_set_location`
  - `test_both_no_region_findings_once_each`
  - `test_gcp_no_region_finding_absent_in_plan_mode`: plan and Kubernetes cases, reaching the `iac_type` guard as 005's test does.
  - `test_gcp_check_name_matches_registry`
- [ ] **Step 2:** Run them and expect FAIL. Record the RED output in the report.
- [ ] **Step 3:** Implement. Fix the counts and docs; regenerate the coverage doc and any affected goldens.
- [ ] **Step 4:** Run the full gate.
- [ ] **Step 5:** Commit `feat(residency): report GCP stacks with no region as EUGUARD_POLICY_006 (TEG-05)`.

### Task 2: Pin Azure/GCP residency in plan mode (T-38, TEG-05)

**Files:**
- Create `tests/fixtures/plan-azure-gcp.json` and `tests/test_plan_residency_multicloud.py`.
- Modify `docs/limitations.md` (~line 67, the "in plan mode only the resource-level residency checks run" sentence) and the README residency section if it says plan mode is AWS-only.

The controller verified at `e74ab76` that a hand-built plan with `azurerm_storage_account.sa` in `location = "eastus"` and `google_storage_bucket.b` in `location = "US"` gives `EUGUARD_POLICY_003` and `EUGUARD_GDPR_004` on the Azure resource, and `EUGUARD_POLICY_004` and `EUGUARD_GDPR_005` on the GCP one. This task pins that behaviour.

- [ ] **Step 1:** Create the fixture: a `terraform show -json`-shaped plan with `planned_values.root_module.resources` and `resource_changes` for four resources:
  - `azurerm_storage_account.us` in `eastus`;
  - `azurerm_storage_account.eu` in `westeurope`;
  - `google_storage_bucket.us` in `US`;
  - `google_storage_bucket.eu` in `EUROPE-WEST3` (check how the GCP table treats case).

  Add `azurerm_monitor_action_group.g` with `location = "global"`.
- [ ] **Step 2:** Write the tests (live Checkov, marked like other live-scan tests):
  - `test_plan_mode_azure_residency`: `.us` gets 003 and 004; `.eu` gets neither.
  - `test_plan_mode_gcp_residency`: the same for 004 and 005.
  - `test_plan_mode_azure_global_location`: the action group gets 003.
  - `test_plan_mode_no_policy_005_006`: neither no-region finding appears.
- [ ] **Step 3:** These pin existing behaviour, so they should pass at once. If one fails, stop and report it as a finding rather than changing production code.
- [ ] **Step 4:** Update the docs to say Azure and GCP resource-level residency checks run in plan mode too, and that the provider-block checks do not. Commit `test: pin Azure/GCP residency checks in plan mode (TEG-05)`.

### Task 3: Release image: scan exactly what is published (T-39, TEG-06/TEG-04)

**Files:** modify `.github/workflows/publish.yml` (job `image`) and `tests/test_ci_workflows.py`. CHANGELOG `### Changed`.

Today the job builds twice, once locally for trivy and once to push. The new flow:
1. **Build and push by digest only:** `docker/build-push-action` (same pinned SHA) with `push: true`, `provenance: mode=max`, `sbom: true`, the existing labels, no `tags`, and `outputs: type=image,name=${{ env.IMAGE_NAME }},push-by-digest=true,name-canonical=true,push=true`. Use `id: build`.
2. **Install trivy:** the existing pinned, checksum-verified step, unchanged.
3. **Scan the pushed digest:** `trivy image --ignore-unfixed --exit-code 1 --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml "${IMAGE_NAME}@${DIGEST}"`, with `DIGEST: ${{ steps.build.outputs.digest }}` passed through `env`, never interpolated into the script. Trivy reads registry credentials from the docker login done earlier in the job; add `TRIVY_USERNAME`/`TRIVY_PASSWORD` from the same token only if the login does not cover it (state which you chose and why).
4. **Tag:** `docker buildx imagetools create -t "${IMAGE_NAME}:${REF_NAME}" "${IMAGE_NAME}@${DIGEST}"`, with `REF_NAME` from `github.ref_name` through `env`.
5. **Attest:** the existing attest step with `subject-digest: ${{ steps.build.outputs.digest }}`, placed after the tag step.

Remove the local `load: true` scan build. Add a YAML comment saying a failed scan leaves an untagged digest in GHCR that no tag points to.

- [ ] **Step 1: Update or replace the iteration-6 publish tests:**
  - `test_publish_image_is_scanned_before_push` → `test_publish_tags_only_after_scan`: the trivy step comes before the `imagetools create` step and the attest step.
  - `test_publish_scans_and_tags_same_digest`: the scan and tag steps both get `steps.build.outputs.digest` through `env`.
  - `test_publish_build_pushes_by_digest_only`: `push-by-digest=true` and no `tags:` key.
  - `test_publish_trivy_pin_matches_ci`: keep it.
  - `test_publish_no_expression_in_run`: no `${{` inside any `run:` of the new steps.
- [ ] **Step 2:** Run them and expect FAIL. Then implement, run them again and expect PASS. Run `actionlint` if it is available; ci.yml installs a pinned one, which you may reuse locally via the same URL and checksum into `<scratchpad>`. Otherwise say it was not run.
- [ ] **Step 3:** Update the iteration-6 CHANGELOG entry for the release scan, or add a new one, to describe build-once. Commit `ci(publish): push by digest, scan that digest, then tag and attest (TEG-06)`.

### Task 4: Deferred cleanups (T-40)

**Files:** `CHANGELOG.md`, `tf_eu_guard/residency.py` (the docstring near lines 189-191), `tools/generate_checkov_coverage.py` (argument parsing) and `tests/test_region_unset_finding.py` (~line 225).

- [ ] **CHANGELOG fixes.**
  - The `EUGUARD_POLICY_005` entries (~lines 88-98) say it "no longer treats…", but 005 is new in this release. Reword to describe the AWS and GCP stderr-warning pattern change.
  - Move the `--counts-file` help sentence into its own bullet, since it is a main-CLI change.
- [ ] **Docstring:** reflow the `residency.py` docstring that iteration 8 left broken.
- [ ] **`tools/generate_checkov_coverage.py`:** switch to `argparse` (`--check`, `--doc PATH`), so `--doc --check` is an error rather than a path. Test: `test_doc_flag_followed_by_flag_is_error`.
- [ ] **`tests/test_region_unset_finding.py`:** the baseline written under the pinned `_today` must not be dated after that day. Pin consistently, or set the baseline timestamp.
- [ ] **Finish:** run the full gate and commit `chore: iteration-8 leftovers (changelog wording, argparse for the coverage tool)`.
