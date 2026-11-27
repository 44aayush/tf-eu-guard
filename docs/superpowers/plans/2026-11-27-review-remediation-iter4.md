# Review remediation, iteration 4, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-21 (severity rubric), T-16 (Azure and GCP residency) and T-20 (emulator test tier) on branch `version_0.10.0`.

**Architecture:**
- **Rubric:** a written rubric, pinned by a family test, with the registry adjusted to it.
- **Azure and GCP residency:** both extend the existing AWS residency design. `tf_eu_guard/regions.py` gains per-cloud tables, and `tf_eu_guard/residency.py` resolves a per-cloud allowlist from the same policy environment variables. New custom checks live beside `checks/gdpr/data_residency.py` and are registry-backed in `registry-azure.yaml` and `registry-gcp.yaml`.
- **Emulator tier:** an opt-in pytest tier (`TFEG_RUN_EMULATOR=1`) plus one CI job with a LocalStack service container pinned by digest.

**Tech Stack:** Python 3.11-3.14, Checkov custom checks (`BaseResourceCheck`, `BaseProviderCheck`), pytest, Terraform 1.17.2, LocalStack 4.9, GitHub Actions.

**Spec:** REVIEW.md TEG-05 (Azure/GCP residency), TEG-11 (severity rubric), section 6 (emulator tier), and TASKS.md T-16, T-20 and T-21.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory, outside the repo. `<venv>` is `<scratchpad>/venv`. Never write the scratchpad's absolute path into a committed file.
- Branch `version_0.10.0` in `/home/dev/tf-eu-guard`.
  - Never create or push tags, never merge into `main`, take no pull-request actions, and do not push.
  - Never rewrite history.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- Supported Python 3.11-3.14; no new runtime dependency. ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, mypy, `tools/check_doc_counts.py` and `tools/generate_coverage_doc.py --check` stay clean.
- Full-suite runs use `TFEG_RUN_CHECKOV=1`; run the full suite after your last code change.
- Registry entries are hedged legal claims, in the style of the surrounding entries. Policy checks are project-policy findings. The Chapter V checks are review signals, not verdicts.
- Region classification fails closed for policy checks: anything not on the allowlist fails. It is conservative for Chapter V checks: only a known third-country region fails.
- Every `uses:` is pinned to a 40-hex SHA with a `# vX.Y.Z` comment, and every container image is pinned by digest.
- Each task adds a CHANGELOG bullet under `## [Unreleased]` in the existing subsections. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.
- The commit trailer names the model that wrote the commit.

## Review Focus

1. **Azure display names:** `location = "West Europe"` and `"westeurope"` classify the same (lower-case, spaces removed). *Pinned by `test_azure_location_normalisation` (Task 2).*
2. **GCP zones and multi-regions:** `europe-west1-b` classifies as `europe-west1`; `EU` is in policy; `US` is a known third country. *Pinned by `test_gcp_location_normalisation` (Task 3).*
3. **AWS behaviour is unchanged:** every existing residency test stays green, and `eusc` still means AWS European Sovereign Cloud only. *Pinned by the existing suite (Tasks 2 and 3).*
4. **A relaxed severity can be restored:** the rubric lowers seven CMK checks, and the CHANGELOG shows how to restore the old level with `severity_overrides`. *Pinned by `test_cmk_family_is_medium` plus the CHANGELOG text (Task 1).*
5. **The emulator tier never runs by accident:** without `TFEG_RUN_EMULATOR=1` the tests skip, so the default suite and Windows/macOS CI are unaffected. *Pinned by `test_emulator_tier_skips_by_default` (Task 4).*

---

### Task 1: Severity rubric (T-21, TEG-11)

**Files:**
- Create: `docs/severity-rubric.md`
- Modify: `tf_eu_guard/mapping/registry-aws.yaml`; `tests/test_registry_rubric.py`; generated docs and counts; `examples/end2end/EXPECTED_FINDINGS.md` wherever these severities appear; CHANGELOG

Rubric families. The test pins exactly these IDs; other checks are outside the rubric for now, and the doc says so:
- **Public exposure of a data store or an admin port: CRITICAL.** `CKV_AWS_17`, `CKV_AWS_20`, `CKV_AWS_70`, `CKV_AWS_87`, `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AZURE_11`, `CKV_AZURE_59`, `CKV_GCP_11`, `CKV_GCP_28`, `CKV_GCP_88`. This raises `CKV_AWS_24` and `CKV_AWS_25` from HIGH.
- **Public-network guardrails (defence in depth against exposure): HIGH.** `CKV2_AWS_6`, `CKV_AWS_53`, `CKV_AWS_54`, `CKV_AWS_55`, `CKV_AWS_56`, `CKV_AWS_38`, `CKV_AZURE_139`, `CKV_AZURE_160`, `CKV_AZURE_48`, `CKV_AZURE_53`, `CKV_GCP_18`. All are unchanged.
- **Data-store encryption at rest: HIGH.** `CKV_AWS_16`, `CKV_AWS_3`, `CKV_AWS_96`, `CKV_AWS_5`, `CKV_AWS_44`. Already HIGH.
- **Customer-managed key instead of a provider-managed key: MEDIUM.** `CKV_AWS_119`, `CKV_AWS_147`, `CKV_AWS_149`, `CKV_AWS_186`, `CKV_AWS_189`, `CKV_AWS_191`, `CKV_AWS_224`, `CKV_AWS_247`, `CKV_AWS_280`, `CKV_AWS_327`, `CKV_AWS_347`, `CKV_AWS_35`. This lowers `119`, `147`, `149`, `247`, `327`, `347` and `35` from HIGH. Rationale: the data is already encrypted with a provider-managed key; a CMK adds key-control depth, which GDPR Art. 32(1)(a) does not itself require.

- [ ] Tests in `tests/test_registry_rubric.py`: `test_public_exposure_family_is_critical`, `test_guardrail_family_is_high`, `test_encryption_at_rest_family_is_high` (exists; keep it), `test_cmk_family_is_medium`, `test_rubric_doc_lists_every_family_id` (every ID in the test sets appears in `docs/severity-rubric.md`). Also check that each ID's `check_name` really belongs to its family (exposure, public network, encryption, CMK/KMS); report any ID you think is misplaced instead of silently moving it.
- [ ] RED, implement, GREEN; regenerate the docs; full gate.
- [ ] CHANGELOG `### Changed`: list the two raised and the seven lowered checks, with a `severity_overrides` example that restores the old levels. Commit `fix(registry): written severity rubric; SSH/RDP world-open CRITICAL, CMK checks MEDIUM (TEG-11)`.

### Task 2: Azure residency (T-16, TEG-05, part 1)

**Files:**
- Modify: `tf_eu_guard/regions.py` (`AZURE_EU_EEA_LOCATIONS`, `AZURE_KNOWN_LOCATIONS`), `tf_eu_guard/residency.py`
- Create: `tf_eu_guard/checks/gdpr/azure_residency.py`
- Modify: `tf_eu_guard/mapping/registry-azure.yaml`; docs (README feature list: remove "AWS only" for Azure; `docs/limitations.md`; `docs/gdpr-mapping.md`); generated docs and counts

**Interfaces:**
- `normalise_azure_location(value: str) -> str`: lower-case, with spaces, hyphens and underscores removed.
- `residency.allowed_regions_from_env(environ, cloud: str = "aws") -> frozenset[str]` (backward compatible).
  - `eu-eea`: the cloud's EU/EEA table.
  - `eusc`: for AWS, the EUSC table (unchanged); for Azure and GCP, the cloud's EU/EEA table. Ruling: EUSC is an AWS partition.
  - `custom`: the same allowlist for every cloud.
- `AZURE_EU_EEA_LOCATIONS`: `northeurope`, `westeurope`, `francecentral`, `francesouth`, `germanywestcentral`, `germanynorth`, `swedencentral`, `swedensouth`, `italynorth`, `polandcentral`, `spaincentral`, `norwayeast`, `norwaywest`, `austriaeast`.
  - Ruling: newer EU regions that could not be verified from an authoritative source (`belgiumcentral`, `denmarkeast`, `finlandcentral`, `greececentral`) are deliberately left out. They fail the policy check, which is the safe direction for a fail-closed gate, until they are verified. A comment in `regions.py` says so.
- `AZURE_KNOWN_LOCATIONS`: the EU/EEA set, plus these known third-country locations: `uksouth`, `ukwest`, `switzerlandnorth`, `switzerlandwest`, `eastus`, `eastus2`, `westus`, `westus2`, `westus3`, `centralus`, `northcentralus`, `southcentralus`, `westcentralus`, `canadacentral`, `canadaeast`, `brazilsouth`, `eastasia`, `southeastasia`, `japaneast`, `japanwest`, `australiaeast`, `australiasoutheast`, `centralindia`, `southindia`, `koreacentral`, `uaenorth`, `southafricanorth`.
- New checks in `azure_residency.py`, each over every `azurerm_*` resource that has a `location` argument:
  - `EUGUARD_POLICY_003` ("Ensure Azure resource locations are within the configured residency policy"): FAILED when the location is off the allowlist, including an unresolved `var.*` reference; UNKNOWN when there is no location.
  - `EUGUARD_GDPR_004` ("Review Azure resource locations outside the EU/EEA for GDPR Chapter V transfer safeguards"): FAILED only for a known third-country location; PASSED for EU/EEA; otherwise UNKNOWN.
- Registry entries mirror `EUGUARD_POLICY_002` and `EUGUARD_GDPR_003` (same articles: `Policy RESIDENCY-001` and GDPR `Art. 44` respectively; severity HIGH), with Azure wording.

- [ ] Tests (`tests/test_residency_azure.py`): `test_azure_location_normalisation`, `test_azure_eu_location_passes`, `test_azure_us_location_fails_both`, `test_azure_uk_location_fails_both` (the UK is a GDPR third country), `test_azure_unverified_eu_location_fails_policy_only` (`belgiumcentral` fails POLICY_003; GDPR_004 is UNKNOWN), `test_azure_unresolved_var_fails_policy_unknown_transfer`, `test_azure_custom_policy`. Also an end-to-end CLI test on the REVIEW.md E5c-style fixture (`tests/fixtures/residency-azure/main.tf` with `location = "eastus"`): both IDs appear.
- [ ] RED, implement, GREEN; regenerate the docs; full gate. CHANGELOG `### Added`. Commit `feat(residency): Azure location policy and Chapter V review checks (TEG-05)`.

### Task 3: GCP residency (T-16, TEG-05, part 2)

**Files:**
- Modify: `tf_eu_guard/regions.py` (`GCP_EU_EEA_LOCATIONS`, `GCP_KNOWN_LOCATIONS`)
- Create: `tf_eu_guard/checks/gdpr/gcp_residency.py`
- Modify: `registry-gcp.yaml`; docs and generated docs

**Interfaces:**
- **Consumes** `allowed_regions_from_env(environ, cloud="gcp")` from Task 2.
- `normalise_gcp_location(value: str) -> str`:
  - lower-case;
  - a zone (`^[a-z]+-[a-z]+[0-9]+-[a-z]$`) maps to its region by dropping the `-x` suffix;
  - the multi-regions `EU`, `US` and `ASIA` become `eu`, `us` and `asia`.
- `GCP_EU_EEA_LOCATIONS`: `europe-west1`, `europe-west3`, `europe-west4`, `europe-west8`, `europe-west9`, `europe-west10`, `europe-west12`, `europe-north1`, `europe-north2`, `europe-central2`, `europe-southwest1`, and the multi-region `eu`. Dual-regions such as `eur4` are left out (unverified, so they fail closed).
- `GCP_KNOWN_LOCATIONS`: the EU set, plus these known third-country locations: `europe-west2` (London), `europe-west6` (Zurich), `us`, `asia`, `us-central1`, `us-east1`, `us-east4`, `us-east5`, `us-south1`, `us-west1`, `us-west2`, `us-west3`, `us-west4`, `northamerica-northeast1`, `northamerica-northeast2`, `southamerica-east1`, `southamerica-west1`, `asia-east1`, `asia-east2`, `asia-northeast1`, `asia-northeast2`, `asia-northeast3`, `asia-south1`, `asia-south2`, `asia-southeast1`, `asia-southeast2`, `australia-southeast1`, `australia-southeast2`, `me-west1`, `me-central1`, `me-central2`, `africa-south1`.
- Checks:
  - `EUGUARD_POLICY_004` (provider `google` `region`, and resource-level `region`, `location` and `zone` on `google_*` resources).
  - `EUGUARD_GDPR_005` (the Chapter V counterpart).
  - Same semantics as Task 2. Provider and resource checks may be separate classes sharing the IDs, as AWS does with POLICY_001 and POLICY_002; if you share IDs, say so in the report.
- Registry entries mirror the AWS ones, with GCP wording.

- [ ] Tests (`tests/test_residency_gcp.py`): `test_gcp_location_normalisation`, `test_gcp_eu_region_and_multiregion_pass`, `test_gcp_london_and_zurich_fail_both`, `test_gcp_us_multiregion_fails_both`, `test_gcp_zone_maps_to_region`, `test_gcp_provider_region_checked`, and a CLI test on a fixture with `region = "us-central1"` and a bucket with `location = "US"`.
- [ ] RED, implement, GREEN; regenerate the docs; full gate. CHANGELOG `### Added`. Commit `feat(residency): GCP location policy and Chapter V review checks (TEG-05)`.

### Task 4: Emulator test tier (T-20)

**Files:**
- Create: `tests/emulator/__init__.py` (if needed), `tests/emulator/conftest.py`, `tests/emulator/test_plan_residency.py`, `tests/emulator/localstack_override.tf`, `tests/emulator/fixtures/no-provider-region/main.tf` with its `.terraform.lock.hcl`
- Modify: `.github/workflows/ci.yml` (new job `emulator`), `README.md` or `CONTRIBUTING.md` (how to run the tier), CHANGELOG

Behaviour:
- Every test in `tests/emulator/` is skipped unless `TFEG_RUN_EMULATOR == "1"`, and also skipped when `terraform` is not on PATH. The endpoint comes from `TFEG_EMULATOR_ENDPOINT` (default `http://127.0.0.1:4566`).
- `test_env_region_is_caught_in_plan_mode`: copy the fixture into `tmp_path` and add the override file. Run `terraform init/plan/show -json` with `AWS_REGION=us-east-1`, then `tf_eu_guard.scan(plan, iac_type="terraform_plan", no_config=True)`. The finding IDs must include `EUGUARD_POLICY_002` and `EUGUARD_GDPR_003`.
- `test_s3_public_access_block_ground_truth`: apply a bucket with all four public-access-block flags false. Read the flags back with `boto3` (already in the lock via Checkov). Assert that they are false and that `CKV_AWS_53` through `56` are in the plan-scan findings. Destroy afterwards.
- `test_emulator_tier_skips_by_default` (in `tests/test_ci_workflows.py`, or a plain test outside the tier): with the variable unset, collecting `tests/emulator` yields only skipped tests.
- The override file never lives inside a scanned fixture.
- Commit the fixture's `.terraform.lock.hcl` (`hashicorp/aws ~> 6.0`, generated with Terraform 1.17.2 via `terraform providers lock -platform=linux_amd64`).
- CI job `emulator`:
  - `runs-on: ubuntu-24.04`, `timeout-minutes: 20`, `needs: [lint]`, default read-only permissions.
  - Service `localstack`: image `localstack/localstack@sha256:59373b4a27dba3ec15c4db0b7455f0cb68c8a42300e2cbbe362b440f9a131697` (the 4.9 community tag, which runs without an auth token), port `4566:4566`, env `SERVICES: s3,sqs,dynamodb,sts,iam`.
  - Steps:
    1. The pinned checkout.
    2. `hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e # v4.0.1` with `terraform_version: 1.17.2` and `terraform_wrapper: false`.
    3. `actions/setup-python`, pinned as in the other jobs.
    4. Install the hashed locks and the project.
    5. Run `pytest tests/emulator -p no:cacheprovider -o addopts=""` with env `TFEG_RUN_EMULATOR: "1"`.
  - zizmor (offline, auditor persona) and actionlint, if available, must stay clean.

- [ ] Before running locally, start LocalStack: `docker run -d --rm --name teg-emu -p 127.0.0.1:4566:4566 -e SERVICES=s3,sqs,dynamodb,sts,iam localstack/localstack@sha256:59373b4a…` (full digest above). Terraform is at `/home/dev/.local/bin/terraform`. Stop the container when done.
- [ ] RED (the tests do not exist), implement, GREEN with `TFEG_RUN_EMULATOR=1`. Then confirm that the default suite skips them, and run zizmor (`<scratchpad>/plan-check/ci-tools-new/bin/zizmor --offline --persona auditor --min-severity informational .`). Full gate. CHANGELOG `### Added`. Commit `test: opt-in LocalStack emulator tier and CI job (REVIEW.md section 6)`.

---

### Iteration close (controller)
- [ ] Final whole-branch review (Opus), one fix wave, scoped re-review.
- [ ] Gate (Haiku) with a fresh image and the recheck harnesses (add Azure/GCP rows: lab `e5c-azure-gcp` now yields POLICY_003/GDPR_004 and POLICY_004/GDPR_005).
- [ ] REVIEW.md "After iteration 4"; TASKS.md; push `version_0.10.0` (no tags).
