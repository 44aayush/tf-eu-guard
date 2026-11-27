# Review remediation, iteration 7, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-30 to T-33 on `version_0.10.0`: iteration-6 code-health leftovers, a `ReportContext` for the report layer, baseline matching for unmapped findings, and a per-release Checkov coverage table.

**Architecture:**
- Task 1 makes small, independent fixes.
- Task 2 is a behaviour-preserving refactor of `tf_eu_guard/cli/reports.py` onto one frozen dataclass, proven byte-identical on every output format.
- Task 3 extends `tf_eu_guard/baseline.py` and the pipeline split, and adds one field to that dataclass.
- Task 4 adds a generator in `tools/` with a committed triage file and a generated doc, checked in CI the way `tools/generate_coverage_doc.py --check` is.

**Tech Stack:** Python 3.11-3.14, pytest, Checkov 3.4.5 (pinned in `requirements.lock`), YAML, GitHub Actions.

**Spec:** REVIEW.md TEG-10 (the per-release table), TEG-17 (`ReportContext`, code health), section 7 "After iteration 6", and the iteration-6 ledger's deferred minors. TASKS.md T-30 to T-33.

## Global Constraints

- `<scratchpad>` is the controller's session scratch directory and `<venv>` is the review venv. Never write a scratchpad absolute path into a committed file.
- Branch `version_0.10.0`.
  - No tags, no merges, no pull-request actions, no pushes.
  - No history rewriting.
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` variables.
- The gate stays clean after your last change: ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check`, `mypy --ignore-missing-imports tf_eu_guard tools`, `tools/check_doc_counts.py`, `tools/generate_coverage_doc.py --check`, and the full suite with `TFEG_RUN_CHECKOV=1`.
- Every user-visible change gets a CHANGELOG entry in the unreleased section.
- Public API: anything importable from `tf_eu_guard` (`tf_eu_guard/__init__.py`, `tf_eu_guard/api.py`) keeps its signature.
- Registry text stays hedged. An "intentionally unmapped" reason states why no honest article link exists; it never claims compliance.
- The commit trailer names the model that wrote the commit. Do not edit REVIEW.md, TASKS.md or `docs/superpowers/`.

## Review Focus

1. **A pre-iteration baseline:** a baseline written before this change, with no `baselined_unmapped` key, still loads, and its `unmapped[]` entries count as known. *Pinned by `test_baseline_matches_unmapped_from_v2_report` (Task 3).*
2. **Legacy array baselines** carry no unmapped entries, so nothing unmapped is matched and nothing crashes. *Pinned by `test_array_baseline_has_no_unmapped_keys` (Task 3).*
3. **The refactor changes no output:** every format's bytes are identical before and after, timestamps and uuids aside. *Pinned by the Task 2 golden comparison.*
4. **The Checkov catalogue drifts on a version bump:** a check in the catalogue that is neither mapped nor triaged appears as `untriaged` and does not fail CI. A registry ID absent from the pinned catalogue fails `--check`. *Pinned by `test_stale_registry_id_fails_check` and `test_untriaged_is_not_an_error` (Task 4).*
5. **Both gates trip on the same findings:** `--fail-on-unmapped` and a counted `--unmapped-severity` print one Fail line, not two. *Pinned by `test_one_fail_line_when_both_unmapped_gates_trip` (Task 1).*

---

### Task 1: Iteration-6 leftovers (T-32)

**Files:**
- Create `tf_eu_guard/json_layout.py`.
- Modify `tf_eu_guard/cli/reports.py`, `tf_eu_guard/provenance.py`, `tf_eu_guard/cli/gating.py`, `tools/check_cloud_region_tables.py` and `tests/emulator/stack.py`.
- Tests next to the existing ones: `tests/test_cli_gating.py`, `tests/test_cloud_region_tables.py`, `tests/test_emulator_stack.py` and the provenance tests.

**Interfaces:**
- Produces `tf_eu_guard.json_layout.resolve_json_format(args: argparse.Namespace | None) -> str`, moved from `cli/reports.py`. `cli/reports.py` re-exports it so existing imports keep working. `provenance.py` imports it at module top; no function-local import remains.

- [ ] **Step 1: Write the failing tests:**
  - `test_one_fail_line_when_both_unmapped_gates_trip`: `fail_on_unmapped=True`, `fail_on_severity="HIGH"`, `unmapped_severity="HIGH"` and one unmapped finding. Exactly one stderr line starts with `Fail:` and mentions unmapped findings: the `--fail-on-unmapped` line. The exit code is `EXIT_FINDINGS`.
  - `test_provenance_records_resolved_json_format`: `--output json` without `--json-format` gives `provenance.options.json_format == "array"`. Find where options are assembled (`provenance.py` ~lines 79-108).
  - `test_require_endpoint_ignores_proxy_env`: with `monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")` and an endpoint served by a local `http.server` thread answering 200 on `/_localstack/health`, `require_endpoint` does not raise.
  - `test_list_keys_are_explicit`: `check_cloud_region_tables.LIST_KEYS == ("eu_eea", "third_country", "unclassified")`.
- [ ] **Step 2:** Run them and expect FAIL.
- [ ] **Step 3: Implement.**
  - Move `resolve_json_format`.
  - In `apply_scan_gate`, skip the `--unmapped-severity` Fail line when `--fail-on-unmapped` already reported the same findings.
  - Provenance records the resolved layout when the output is JSON.
  - `require_endpoint` opens the URL through `urllib.request.build_opener(urllib.request.ProxyHandler({}))`.
  - `load_snapshot` iterates a module constant `LIST_KEYS` instead of `REQUIRED_KEYS[2:]`.
- [ ] **Step 4:** Run the tests and the full gate, and expect PASS. Add CHANGELOG `### Changed` lines for the single Fail line and the provenance option.
- [ ] **Step 5:** Commit `refactor: iteration-6 leftovers (json_layout module, one unmapped Fail line, proxy-free health check)`.

### Task 2: `ReportContext` for the report layer (T-33, TEG-17)

**Files:**
- Create `tf_eu_guard/cli/report_context.py`.
- Modify `tf_eu_guard/cli/reports.py` and its callers (grep the function names; expect `cli/app.py` and `cli/pipeline.py`).
- Tests: create `tests/test_report_context.py`.

**Interfaces:**
- Produces a frozen dataclass `ReportContext` with these fields:
  - `args: argparse.Namespace`
  - `findings: list[EnrichedFinding]`
  - `unmapped: list[dict[str, Any]]`
  - `suppressed: list[EnrichedFinding]`
  - `suppressed_unmapped: list[dict[str, Any]]`
  - `waived: list[EnrichedFinding]`
  - `baselined: list[EnrichedFinding]`
  - `checkov_version: str | None`
  - `requirements: list[RequirementResult]`
  - `registry: LoadedRegistry | None`
  - `weakening_settings: list[str]`
  - `provenance: dict[str, Any] | None`

  List fields default to empty, and the field set is exactly the set of parameters threaded through `reports.py` today. If a function threads a parameter that is not listed, add it and say so in the report.
- Produces `ReportContext.from_result(args, result) -> ReportContext`, where `result` is the pipeline's scan-result object (read `cli/pipeline.py` for its name).
- Every report function that currently takes 6 or more of these parameters takes `ctx: ReportContext`, plus only the arguments specific to that format. Functions that are part of the public API (Global Constraints) keep their signatures and build a context internally.

- [ ] **Step 1: Golden capture before any edit.** Write `tests/test_report_context.py::test_reports_are_byte_identical`. It runs the CLI on a fixed `--checkov-json` fixture (reuse one from `tests/`) with `--no-config` for every `--output` value: `dev`, `security`, `auditor`, `sarif`, `json --json-format object`, `json --json-format array`, `markdown` and `csv`. Each run uses `--show-unmapped`, and it writes to `--output-file` where the format supports it. It normalises timestamps and uuids with one regex helper and compares against golden files committed under `tests/fixtures/report-golden/`, generated from the pre-refactor code in this step.
- [ ] **Step 2:** Run it on the unchanged code and expect PASS. Commit the goldens alone: `test: golden report outputs before the ReportContext refactor`.
- [ ] **Step 3: Implement** `ReportContext` and move the report functions onto it. Delete the parameter lists the dataclass replaces; keep no compatibility shims for private functions.
- [ ] **Step 4:** Run the golden test (unchanged goldens must PASS), `test_report_context_from_result_copies_fields` (each field equals the result attribute it came from), and then the full gate. Report `git diff --stat` for `cli/reports.py`; the net line change should be negative.
- [ ] **Step 5:** Commit `refactor(cli): pass one ReportContext through the report layer (TEG-17)`. Add no CHANGELOG entry: the change is internal.

### Task 3: Baseline matching for unmapped findings (T-30, TEG-10)

**Files:** modify `tf_eu_guard/baseline.py`, `tf_eu_guard/cli/pipeline.py` (the split near the `--baseline` block, ~line 246), `tf_eu_guard/cli/report_context.py` (from Task 2), the JSON object report in `tf_eu_guard/cli/reports.py` and `tf_eu_guard/schemas/report.schema.json`. Docs: correct the "unmapped findings are never baselined" statements added in iteration 6 (grep "never baselined" in README.md, docs/, `tf_eu_guard/cli/parser.py`, `action.yml`). Waivers still never cover unmapped findings; keep those statements. Tests go in `tests/test_baseline.py` and the CLI gating tests. CHANGELOG `### Changed`.

**Interfaces:**
- `Baseline` gains `unmapped_keys: frozenset[Key]`. It is built from the object report's `unmapped[]` plus `baselined_unmapped[]` (a missing key reads as `[]`), skipping entries flagged `suppressed`. Keys use `finding_key(check_id, resource, file_path)`. The array format gives `frozenset()`.
- `ScanResult` (or the pipeline's result type) gains `baselined_unmapped: list[dict[str, Any]]`, and `ReportContext` gains the same field.
- The JSON object report gains a top-level `"baselined_unmapped"` array whose entries have the same shape as `"unmapped"` entries. The schema declares it, and `schema_version` follows the repo's existing rule for additive fields (read how `baselined` was introduced).

Rulings:
- With `--baseline`, active unmapped findings whose key is in `unmapped_keys` move out of `unmapped` into `baselined_unmapped`. The gate, `--fail-on-unmapped` and `--unmapped-severity` therefore see only new unmapped findings.
- `--changed-since` filters `baselined_unmapped` like the other groups.
- The stderr baseline line becomes `baseline: {path} ({when}, {n} known finding(s) matched, {m} unmapped)`, where `n` is the mapped count as today.
- Non-JSON formats change only through the smaller unmapped count.

- [ ] **Step 1: Write the failing tests:**
  - `test_baseline_matches_unmapped_from_v2_report`: an object report with `unmapped: [{check_id: "CKV_ZZZ_999", resource: "aws_s3_bucket.a", file_path: "/main.tf"}]` and no `baselined_unmapped` key. `unmapped_keys == {("CKV_ZZZ_999", "aws_s3_bucket.a", "main.tf")}`.
  - `test_array_baseline_has_no_unmapped_keys`.
  - `test_suppressed_unmapped_entries_not_known`.
  - `test_unmapped_severity_with_baseline_only_new_fail`: CLI with a crafted `--checkov-json` (as in the iteration-6 `--unmapped-severity` end-to-end test). Write a baseline with `--output json --json-format object --output-file`, then rerun on the same input with `--baseline`, `--fail-on-severity HIGH`, `--unmapped-severity HIGH`. The exit is 0 and stderr has `1 unmapped)`. Adding a second unmapped failure gives exit 1.
  - `test_baselined_unmapped_in_json_object`: the rerun's object report has one `baselined_unmapped` entry and `unmapped == []`, and it validates against the schema.
  - `test_baseline_chain_keeps_unmapped_known`: a baseline written from a report that itself has `baselined_unmapped` still matches.
- [ ] **Step 2:** Run them and expect FAIL.
- [ ] **Step 3:** Implement per the rulings and correct the docs.
- [ ] **Step 4:** Run the tests and the full gate, and expect PASS.
- [ ] **Step 5:** Commit `feat(baseline): match unmapped findings against the baseline (TEG-10)`.

### Task 4: Per-release Checkov coverage table (T-31, TEG-10)

**Files:**
- Create `tools/generate_checkov_coverage.py`, `tools/checkov_triage.yaml`, `docs/checkov-coverage.md` (generated) and `tests/test_checkov_coverage.py`.
- Modify `.github/workflows/ci.yml` and `tools/README.md`.
- Link the new doc from `docs/check-mapping-table.md` ("Checks still intentionally unmapped") and from README.md's docs list.
- CHANGELOG `### Added`.

**Interfaces:**
- `catalogue() -> dict[str, str]`: Checkov check ID to check name for the installed Checkov. It covers Terraform resource, data, provider and graph checks (`CKV_` and `CKV2_`) and Kubernetes checks. It keeps the prefixes `CKV_AWS_`, `CKV2_AWS_`, `CKV_AZURE_`, `CKV2_AZURE_`, `CKV_GCP_`, `CKV2_GCP_`, `CKV_K8S_` and `CKV2_K8S_`, and the cloud-agnostic `CKV_TF_` ones. Use Checkov's Python registries; if graph checks are not reachable that way, use `checkov --list` output and say which in the report.
- `classify(catalogue, mapped_ids, triage) -> list[Row]`, where `Row` is a `NamedTuple(check_id, name, provider, status, reason)` and `status` is one of `"mapped"`, `"intentionally unmapped"` or `"untriaged"`.
- `stale_ids(catalogue, mapped_ids) -> list[str]`: registry IDs with one of those prefixes that are absent from the catalogue.
- `render(rows, checkov_version) -> str`: the Markdown doc. It has a header naming the Checkov version (from `checkov.version.version`), a summary table per provider (total, mapped, intentionally unmapped, untriaged), then one table per provider sorted by ID.
- CLI: `python tools/generate_checkov_coverage.py` writes the doc. `--check` exits 1 when the doc is stale or `stale_ids` is non-empty, and 0 otherwise. Untriaged checks are never an error.
- `tools/checkov_triage.yaml` has the shape `intentionally_unmapped: {CHECK_ID: reason}`. Seed it with the password-policy family `CKV_AWS_10` to `CKV_AWS_15`, with the reason from docs/check-mapping-table.md: represented by the mapped `CKV_AWS_9` account-level check. Add no other entries. Every other unmapped check stays honestly `untriaged`. An ID listed in both the triage file and a registry is an error in `--check`.

- [ ] **Step 1: Write the failing tests** with small in-memory catalogues; none needs Checkov:
  - `test_classify_statuses`
  - `test_untriaged_is_not_an_error`
  - `test_stale_registry_id_fails_check`
  - `test_triage_and_mapping_conflict_fails`
  - `test_render_summary_counts`
  - `test_doc_is_current`, which runs only when Checkov is importable and runs `--check`.
- [ ] **Step 2:** Run them and expect FAIL. Then implement, generate `docs/checkov-coverage.md`, and run them again: PASS.
- [ ] **Step 3:** If `stale_ids` is non-empty on the real registries, do not delete registry entries. List them in the report and make `--check` pass only via an explicit `known_stale: {ID: reason}` key in `tools/checkov_triage.yaml` that the controller will rule on.
- [ ] **Step 4:** Add a CI step running `python tools/generate_checkov_coverage.py --check` in the job that already has Checkov installed, next to the existing Checkov-dependent checks. Document the tool in `tools/README.md`, including that a Checkov bump requires regenerating the doc.
- [ ] **Step 5:** Run the full gate. Commit `docs: per-release Checkov coverage table (TEG-10)`.
