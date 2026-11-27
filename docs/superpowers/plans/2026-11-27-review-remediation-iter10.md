# Review remediation, iteration 10, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-41 and T-42 on `version_0.10.0`. T-41 hardens the release image job. T-42 sharpens the GCP no-region finding and its tests.

**Architecture:**
- Task 1 is a workflow-only change in `.github/workflows/publish.yml`, pinned by `tests/test_ci_workflows.py`.
- Task 2 extends `_GCP_GLOBAL_TYPES` in `tf_eu_guard/residency.py`, sharpens the tests and adds one live-Checkov GCP test.

**Tech Stack:** Python 3.11-3.14, pytest, GitHub Actions.

**Spec:** REVIEW.md TEG-06/TEG-04, TEG-05, and section 7 "After iteration 9". TASKS.md T-41 and T-42. The iteration-9 ledger lists the deferred minors.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is the review venv. Never write a scratchpad absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
  - Never run the publish workflow.
- The gate stays clean after your last change: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, `mypy --ignore-missing-imports tf_eu_guard tools`, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, `tools/generate_checkov_coverage.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1`.
- Every user-visible change gets a CHANGELOG entry in the unreleased section. Fold it into the existing unreleased entry for the same feature where one exists; GCP residency, `EUGUARD_POLICY_006` and the release scan are all unreleased.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **A tag that drifts from the scanned digest fails the job:** the post-tag check compares the digest the tag resolves to with `steps.build.outputs.digest`, and exits non-zero on a mismatch. *Pinned by `test_publish_verifies_tag_digest` (Task 1).*
2. **A global type that does take a location** must not be excluded: every new `_GCP_GLOBAL_TYPES` entry is checked against the provider docs. *Pinned by the citations in the report and `test_gcp_global_types_excluded` (Task 2).*
3. **The matches-warning test must assert outcomes:** it fails if both functions return `None` for every case. *Pinned by the `expected` column (Task 2).*

---

### Task 1: Release image hardening (T-41)

**Files:** modify `.github/workflows/publish.yml` (job `image`) and `tests/test_ci_workflows.py`. CHANGELOG: fold into the unreleased release-scan entry.

Rulings:
- Add `--image-src remote` to the trivy scan of `${IMAGE_NAME}@${DIGEST}`.
- After the `imagetools create` tag step, and before the attest step, add a step named `Verify the tag resolves to the scanned digest`. With `IMAGE_NAME`, `REF_NAME` and `DIGEST` passed through `env`, it reads the tag's digest with `docker buildx imagetools inspect "${IMAGE_NAME}:${REF_NAME}" --format '{{json .Manifest}}'` and extracts `.digest` with `jq -r .digest` (jq is on ubuntu-24.04 runners). It fails with `::error::tag ${REF_NAME} resolves to ${actual}, scanned ${DIGEST}` and exit 1 when they differ.
- Add a YAML comment on the tag step saying the tag keeps the scanned digest only because `sbom` and `provenance` make the build an index.
- Out of scope: no automatic deletion of the untagged digest on failure. Deleting published package versions is an irreversible action left to the maintainer.

- [ ] **Step 1: Write the failing tests:**
  - `test_publish_trivy_reads_registry`: the scan step's `run` contains `--image-src remote`.
  - `test_publish_verifies_tag_digest`: the verify step sits between the tag and attest steps, its `env` has `DIGEST: ${{ steps.build.outputs.digest }}`, and its `run` contains `imagetools inspect` and `exit 1`.
  - `test_publish_order_build_scan_tag_verify_attest`: the full order is build, scan, tag, verify, attest.
  - The existing `test_publish_no_expression_in_run` covers the new step.
- [ ] **Step 2:** Run them and expect FAIL (record the output). Then implement.
- [ ] **Step 3:** Run them and expect PASS. Then run the pinned actionlint at `<scratchpad>/actionlint/actionlint -no-color .github/workflows/publish.yml`; the controller gives you the path. Then run the full gate.
- [ ] **Step 4:** Commit `ci(publish): verify the release tag resolves to the scanned digest (TEG-06)`.

### Task 2: GCP no-region follow-ups (T-42, TEG-05)

**Files:** modify `tf_eu_guard/residency.py` (`_GCP_GLOBAL_TYPES`), `tests/test_region_unset_finding.py`, `tools/generate_checkov_coverage.py` (`allow_abbrev=False`), `tests/test_checkov_coverage.py`, and `docs/limitations.md` if it lists examples of global types.

- [ ] **Step 1: Candidate global types.** For each of `google_compute_route`, `google_compute_url_map`, `google_compute_backend_service`, `google_compute_backend_bucket`, `google_compute_ssl_certificate`, `google_compute_managed_ssl_certificate`, `google_compute_health_check`, `google_compute_target_http_proxy`, `google_compute_target_https_proxy`, `google_compute_ssl_policy`, `google_compute_security_policy`, `google_compute_instance_template`, `google_compute_image` and `google_compute_snapshot`:
  - Read the provider doc source, `https://github.com/hashicorp/terraform-provider-google/tree/main/website/docs/r/<name>.html.markdown`. Iteration 9 used this source because the rendered registry pages are JS-only.
  - Add the type to `_GCP_GLOBAL_TYPES` only if it has no top-level `region`, `location` or `zone` argument.
  - Record every URL and verdict in the report. Types with a regional counterpart, such as `google_compute_region_*`, stay counted.
  - Any type that stores data, such as images, snapshots and instance templates, needs care. If the doc shows a `storage_locations` or similar residency argument, do not add it, and say so.
- [ ] **Step 2: Failing tests first:**
  - `test_gcp_global_types_excluded`: parametrised over the newly added types. Each alone gives no 006 and no warning.
  - Rework the parametrised `test_gcp_no_region_finding_matches_warning` with an `expected: bool` column. Add the case from `tests/test_residency.py` that uses `EUGUARD_POLICY_003` on `azurerm_x.y` under `custom_checks_loaded=False`, with the expected value that test asserts for the warning.
  - `test_gcp_no_region_finding_on_source_scan`: a live-Checkov test, marked like `test_no_region_finding_on_source_scan`. Use a tmp dir with `terraform { required_providers { google = { source = "hashicorp/google" } } }` and one `google_compute_instance` with no zone, no provider block and no location anywhere. Exactly one `EUGUARD_POLICY_006`.
  - `test_coverage_tool_rejects_abbreviations`: `--ch` exits 2.
- [ ] **Step 3:** Implement, then run the tests and the full gate.
- [ ] **Step 4:** Fold the change into the unreleased `EUGUARD_POLICY_006` CHANGELOG entry. Commit `fix(residency): more global GCP types, sharper no-region tests (TEG-05)`.
