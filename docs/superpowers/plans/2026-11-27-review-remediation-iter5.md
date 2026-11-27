# Review remediation, iteration 5, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-22 (rubric follow-up), T-23 (Azure/GCP region-table drift check) and T-24 (emulator-tier robustness) on `version_0.10.0`.

**Architecture:** Registry and rubric edits, pinned by the existing family tests. A committed region snapshot plus a check tool, mirroring `tools/check_region_drift.py`. Test-only fixes to `tests/emulator` and the CI job.

**Tech Stack:** Python 3.11-3.14, pytest, YAML registries, GitHub Actions.

**Spec:** REVIEW.md TEG-05 and TEG-11 (section 7, "After iteration 4"), and TASKS.md T-22 to T-24.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is `<scratchpad>/venv`. Never write the scratchpad's absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- The gate stays clean: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, mypy, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1` after your last change.
- Registry text stays hedged. Every severity change goes in the CHANGELOG `### Changed` with its gate effect.
- Before calling anything verified or unverified, cite the authoritative source you checked (URL) in the report.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **Existing rubric families stay intact:** every family test from iteration 4 still passes. *Pinned by `tests/test_registry_rubric.py` (Task 1).*
2. **A table edit that drops a region is caught:** removing a region from `regions.py` without updating the snapshot fails the drift test. *Pinned by `test_region_tables_match_snapshot` (Task 2).*
3. **A failed emulator apply still cleans up:** resources are destroyed even when `apply()` fails part way. *Pinned by `test_stack_destroys_after_failed_apply` (Task 3).*

---

### Task 1: Rubric follow-up (T-22, TEG-11)

**Files:** `registry-aws.yaml`, `registry-gcp.yaml`, `registry-azure.yaml`, `docs/severity-rubric.md`, `tests/test_registry_rubric.py`, generated docs and counts, `examples/end2end/EXPECTED_FINDINGS.md` where affected, CHANGELOG.

Rulings:
1. **KMS-by-default checks** `CKV_AWS_173`, `CKV_AWS_26`, `CKV_AWS_145`, `CKV_AWS_136` and `CKV_GCP_38`. For each, check the provider's documentation for default encryption at rest:
   - If the service encrypts by default with a provider-managed key, move the check to the customer-managed-key family (MEDIUM) and hedge its risk text the way the 12 CMK checks are hedged.
   - If the service does not encrypt by default, add the check to the data-store encryption-at-rest family (HIGH) and leave its text claim-accurate.
   - Report the URL you used for each check.
2. **New family: web port open to the internet, MEDIUM.** It contains `CKV_AWS_260` (port 80) and `CKV_AZURE_160` (HTTP restricted from the internet). This lowers `CKV_AZURE_160` from HIGH. Rationale: a public web tier on port 80 is often intended, and admin ports already sit in the CRITICAL exposure family.

- [ ] Tests: add `test_web_port_family_is_medium`. Extend the CMK and encryption-at-rest family tuples per ruling 1. Every listed ID must appear under its own heading in the rubric doc.
- [ ] RED, implement, GREEN, then the full gate. Commit `fix(registry): rubric follow-up for KMS-by-default and port-80 checks (TEG-11)`.

### Task 2: Region-table drift check for Azure and GCP (T-23, TEG-05)

**Files:** create `tools/region_snapshots/azure.json`, `tools/region_snapshots/gcp.json` and `tools/check_cloud_region_tables.py`; tests `tests/test_cloud_region_tables.py`; document both the tool and the refresh procedure in `tools/README.md`.

**Interfaces:**
- Each snapshot is `{"source": <url>, "verified": "2026-11-27", "eu_eea": [...], "third_country": [...], "unclassified": [...]}`:
  - Azure source: `https://learn.microsoft.com/en-us/azure/reliability/regions-list`.
  - GCP source: `https://docs.cloud.google.com/compute/docs/regions-zones`.
  - Seed the lists from the current `regions.py` tables.
  - `unclassified` holds known-but-deliberately-unlisted codes (Azure `finlandcentral` and `greececentral`; GCP dual-regions such as `eur4`).
- `check_cloud_region_tables.py` exits 1 when any table entry is missing from its snapshot class, any snapshot entry is missing from its table, or an EU/EEA code appears in a third-country table. Otherwise it prints OK.
- Do not fetch the network in tests.

- [ ] Tests:
  - `test_region_tables_match_snapshot`.
  - `test_drift_check_fails_on_missing_region` (monkeypatch a table).
  - `test_snapshot_has_source_and_date`.
- [ ] Add a CI step to the `lint` job (or the job that already runs `check_region_drift.py`) that runs the new tool.
- [ ] RED, implement, GREEN, then the full gate. Commit `test: Azure/GCP region-table snapshot drift check (TEG-05)`.

### Task 3: Emulator-tier robustness (T-24)

**Files:** `tests/emulator/test_plan_residency.py`, `tests/emulator/conftest.py`, `tests/test_ci_workflows.py`, `.github/workflows/ci.yml`.

Changes:
1. Move `apply()` inside the `try`, and add a unique per-run suffix to the bucket name.
2. A failure in `destroy()` must not hide the original assertion: log the cleanup error and re-raise the original.
3. Add a LocalStack health check in CI: service `options: >- --health-cmd "curl -fs http://localhost:4566/_localstack/health" --health-interval 5s --health-timeout 5s --health-retries 20`.
4. The default-skip test must assert that tests were skipped and none passed or failed, without hard-coding the count.
5. The Terraform subprocess environment drops every `AWS_*` variable except `AWS_REGION` and the emulator credentials it sets itself.

- [ ] Tests:
  - `test_stack_destroys_after_failed_apply` (a unit test with a stubbed runner, no LocalStack needed).
  - `test_emulator_env_scrubs_aws_variables`.
  - The skip-test change.
  - The CI-job test asserts the health-cmd.
- [ ] RED, implement, GREEN. If LocalStack is available, run the tier once: start `localstack/localstack@sha256:59373b4a27dba3ec15c4db0b7455f0cb68c8a42300e2cbbe362b440f9a131697` on 127.0.0.1:4566 and stop it afterwards. Then the full gate. Commit `test: harden the emulator tier (T-24)`.

### Iteration close (controller)
- [ ] Final review (Opus), one fix wave, re-review. Gate (Haiku). REVIEW.md "After iteration 5"; TASKS.md; push `version_0.10.0` (no tags).
