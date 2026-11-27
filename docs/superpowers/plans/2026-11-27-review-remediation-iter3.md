# Review remediation, iteration 3, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close TASKS.md T-13, T-14, T-15, T-17, T-18 and T-19 (REVIEW.md TEG-08, TEG-10, TEG-11, TEG-14, TEG-16, TEG-17) on branch `version_0.10.0`. T-16 (Azure/GCP residency) and T-20 (emulator tier) move to iteration 4.

**Architecture:** Small, independent changes: one in `cli/pipeline.py`, three in `checkov/process.py`, one Action input, and one registry and docs change. Tasks that share `process.py` run one after another.

**Tech Stack:** Python 3.11-3.14, pytest, bash (composite Action), YAML registries, the generated docs tools in `tools/`.

**Spec:** `REVIEW.md` TEG-08, TEG-10, TEG-11, TEG-14, TEG-16 and TEG-17 (all re-verified on `227b79e`), and `TASKS.md`.

## Global Constraints

- Branch `version_0.10.0` in `/home/dev/tf-eu-guard`.
  - Never create or push tags, never merge into `main`, take no pull-request actions, and do not push.
  - Never rewrite history (no `filter-branch`, rebase or amend of commits you did not create in this task).
  - Never `git checkout` or revert files you did not change.
  - Never export `GIT_*` environment variables while running anything.
- Supported Python 3.11-3.14; no new runtime dependency. ruff, `git ls-files '*.py' '*.md' | xargs ruff format --check` and `mypy --ignore-missing-imports tf_eu_guard tools` stay clean.
- `<venv>` is `/tmp/claude-1000/-home-dev-tf-eu-guard/231e1cf5-a406-4886-872c-312b008715d1/scratchpad/venv`. Full-suite runs use `TFEG_RUN_CHECKOV=1`; run the full suite again after your last code change.
- Action inputs reach the script only through `env:`. No bash-4-only constructs.
- Untrusted strings printed to a terminal or stderr go through `tf_eu_guard.reporting.untrusted.sanitize`.
- Each task adds a bullet under `## [Unreleased]` in `CHANGELOG.md`, in the existing subsections. Do not edit `REVIEW.md`, `TASKS.md` or `docs/superpowers/`.
- The commit trailer names the model that wrote the commit (`Co-Authored-By: Claude <Model> 5.5 <noreply@anthropic.com>`).

## Review Focus

1. **Framework filtering keeps the caller's objects intact:** after `filter_findings_by_framework(findings, "gdpr")`, the original `EnrichedFinding` objects still carry their NIS2 articles. *Pinned by `test_filter_does_not_mutate_input` (Task 1).*
2. **The environment allowlist keeps networking working:** `HTTPS_PROXY`, `NO_PROXY`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` and `LC_ALL` still reach Checkov, so `--online` works behind a corporate proxy. *Pinned by `test_checkov_environment_keeps_proxy_and_locale` (Task 3).*
3. **Windows still works:** `SYSTEMROOT`, `PATHEXT`, `TEMP` and `USERPROFILE` are kept. *Pinned by `test_checkov_environment_keeps_windows_essentials` (Task 3).*
4. **A module inside the root does not warn:** `source = "./modules/x"` produces no warning. *Pinned by `test_local_module_inside_root_does_not_warn` (Task 4).*
5. **Registry edits keep the generated docs in sync:** `tools/check_doc_counts.py` and `tools/generate_coverage_doc.py --check` pass. *Pinned in Task 6, Step 4.*

---

### Task 1: No in-place mutation in `filter_findings_by_framework` (T-19, TEG-17)

**Files:** `tf_eu_guard/cli/pipeline.py` (`filter_findings_by_framework`). Test: `tests/test_cli_scan.py` or the existing test module for framework filtering.

**Interface:** the signature is unchanged. Build new objects with `dataclasses.replace(finding, articles=..., risk_explanation=...)` and never assign to the input's attributes.

- [ ] Tests:
  - `test_filter_does_not_mutate_input`: a finding with one NIS2 and one GDPR article, filtered to `"gdpr"`. The returned finding has one article; the original still has two and its original risk text.
  - `test_filter_all_returns_same_findings`.
- [ ] RED, implement, GREEN, full gate. CHANGELOG `### Fixed`. Commit `fix(cli): framework filtering returns new findings instead of mutating them (TEG-17)`.

### Task 2: Self-check for a replaced `hcl2` module (T-17, TEG-14)

**Files:** `tf_eu_guard/checkov/process.py` (a new `check_hcl2_module() -> None`, called first in `run_checkov`), README install section. Test: `tests/test_checkov_process.py`.

**Interface:** `check_hcl2_module()` imports `hcl2`. If the import fails, or the module lacks `START_LINE` (the attribute that Checkov's fork `bc-python-hcl2` provides), it raises `CheckovRuntimeError` (exit 3) with this message: `"the installed 'hcl2' module is not Checkov's bc-python-hcl2 (another package, often python-hcl2, replaced it), so Checkov cannot parse Terraform. Install tf-eu-guard in its own environment: uv tool install tf-eu-guard (or pipx install tf-eu-guard)."` It runs only for the `terraform` and `terraform_plan` IaC types.

- [ ] Tests:
  - `test_hcl2_self_check_passes_with_bc_fork`.
  - `test_hcl2_self_check_rejects_foreign_module`: monkeypatch `sys.modules["hcl2"]` to a `types.ModuleType("hcl2")` without `START_LINE`. Expect `CheckovRuntimeError` whose message contains `"bc-python-hcl2"`.
  - `test_run_checkov_reports_foreign_hcl2_before_running`: with the foreign module, `subprocess.run` is never called.
- [ ] RED, implement, GREEN, full gate. CHANGELOG `### Added`. Commit `feat(checkov): explain a replaced hcl2 module instead of a traceback (TEG-14)`.

### Task 3: Allowlist the Checkov environment (T-18, TEG-16)

**Files:** `tf_eu_guard/checkov/process.py` (`checkov_environment`), and `docs/limitations.md` or `SECURITY.md`, wherever the scrubbed variables are described. Test: `tests/test_checkov_process.py`.

**Interface:** `checkov_environment(extra)` keeps only the following variables, then applies `extra`:
- Exact names (matched case-sensitively; `SYSTEMROOT` and similar are also matched case-insensitively on Windows): `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LANGUAGE`, `TZ`, `TMPDIR`, `TEMP`, `TMP`, `SYSTEMROOT`, `SYSTEMDRIVE`, `WINDIR`, `COMSPEC`, `PATHEXT`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PROGRAMDATA`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `no_proxy`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`.
- Every name that starts with `LC_`.

Everything else is dropped, including `CKV_*`, `BC_*`, `PRISMA_*`, `CHECKOV_*`, `GIT_*`, `PYTHON*` and the residency variables, which only arrive through `extra`. Remove the now-unused denylist constants, or keep them only if a public import needs them; check `tf_eu_guard/checkov_runner.py`, which re-exports `_CHECKOV_CONFIG_ENV_VARS`.

- [ ] Tests:
  - `test_checkov_environment_drops_unknown_variables` (`CHECKOV_CREATE_GRAPH`, `CKV_FRAMEWORK`, `BC_API_KEY`, `GIT_DIR`, `FOO`).
  - `test_checkov_environment_keeps_proxy_and_locale`.
  - `test_checkov_environment_keeps_windows_essentials`.
  - `test_checkov_environment_applies_extra`.
  - The existing scrub tests stay green, adjusted if they assumed the denylist.
- [ ] RED, implement, GREEN. Full gate with `TFEG_RUN_CHECKOV=1`, so that real Checkov runs prove it still works under the allowlist. CHANGELOG `### Security`. Commit `fix(checkov): pass Checkov an allowlisted environment (TEG-16)`.

### Task 4: Warn on local modules outside the scan root (T-13, TEG-08)

**Files:** `tf_eu_guard/checkov/process.py` (a new `local_modules_outside_root(target, excludes=()) -> list[tuple[Path, str, Path]]` next to `find_remote_modules`, and its call in `run_checkov` for `iac_type == "terraform"`), README symlink-boundary paragraph. Test: `tests/test_checkov_process.py`.

**Interface:**
- A module call is local when its `source` starts with `./` or `../`. Resolve it as `(file.parent / source).resolve()`. It is reported when the result is not inside the resolved target.
- Warning, printed once with up to 10 entries and `sanitize()`d values: `Warning: local module source(s) outside the scan root: module.<name> (<source>) in <file> resolves to <path>[; ...]. Checkov scans these files, but they are not covered by the scan-root symlink boundary; scan their common parent directory instead.`
- No exit-code change. Reuse the HCL parsing already done by `find_remote_modules`; do not parse each file twice. Refactor into one pass that returns both lists if that is cleaner.

- [ ] Tests:
  - `test_local_module_outside_root_warns` (REVIEW.md E4 layout).
  - `test_local_module_inside_root_does_not_warn`.
  - `test_remote_module_not_reported_as_local`.
- [ ] RED, implement, GREEN, full gate. Lab check: `<venv>/bin/tf-eu-guard scan <scratchpad>/lab/e4-module/root` prints the warning. CHANGELOG `### Added`. Commit `feat(checkov): warn when a local module source leaves the scan root (TEG-08)`.

### Task 5: `fail-on-unmapped` Action input (T-14, TEG-10)

**Files:** `action.yml` (new input, default `'false'`; when `is_true`, pass `--fail-on-unmapped`), README inputs table. Test: `tests/test_action.py`.

- [ ] Tests: `test_action_passes_fail_on_unmapped` (values true and Yes pass the flag; false and empty do not); add the input to `test_action_declares_new_inputs`; add `FAIL_ON_UNMAPPED` to the empty-input list in `_run_action`.
- [ ] RED, implement, GREEN; shellcheck on the extracted run block; full gate. CHANGELOG `### Added`. Commit `feat(action): fail-on-unmapped input (TEG-10)`.

### Task 6: Registry fixes (T-15, TEG-11)

**Files:** `tf_eu_guard/mapping/registry-aws.yaml`, generated docs (regenerate them with the repo's tools: `python tools/generate_coverage_doc.py` and whatever `tools/check_doc_counts.py` checks, including README badge counts), `docs/nis2-mapping.md` and `docs/gdpr-mapping.md` where they list these checks. Test: `tests/test_registry_semantics.py` (or a new `tests/test_registry_rubric.py`).

Exact changes:
1. **`CKV_AWS_288`:** remove the GDPR `Art. 4(12)` and `Art. 33` articles. Keep or add GDPR `Art. 32(1)(b)` and NIS2 `Art. 21(2)(i)`, with canonical titles from `ARTICLE_TITLES`. The risk text may still say an exfiltration path could lead to a breach, but no article may claim one.
2. **Encryption at rest is one severity, HIGH:** `CKV_AWS_96` (Aurora), `CKV_AWS_5` (Elasticsearch) and `CKV_AWS_44` (Neptune) go from CRITICAL to HIGH, matching `CKV_AWS_16` and `CKV_AWS_3`. Rubric: public exposure is CRITICAL; missing encryption at rest is HIGH.
3. **Map `CKV2_AWS_27`** ("Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled"): same articles, severity and remediation style as `CKV2_AWS_30`, adapted to `aws_rds_cluster_parameter_group`.
4. **Map `CKV2_AWS_34`** ("AWS SSM Parameter should be Encrypted"): NIS2 `Art. 21(2)(h)` and GDPR `Art. 32(1)(a)`, severity MEDIUM. Remediation: `type = "SecureString"` with a KMS key.

- [ ] Tests:
  - `test_encryption_at_rest_family_has_one_severity`: `{CKV_AWS_16, CKV_AWS_96, CKV_AWS_5, CKV_AWS_44, CKV_AWS_3}` all have severity HIGH.
  - `test_ckv_aws_288_cites_no_breach_articles`.
  - `test_new_mappings_present` (CKV2_AWS_27 and CKV2_AWS_34).
- [ ] RED, implement, GREEN. Step 4: run `<venv>/bin/python tools/check_doc_counts.py` and `<venv>/bin/python tools/generate_coverage_doc.py --check` (regenerate first). Full gate. The smoke baselines in `tools/smoke_baselines.json` may need a raise if counts change; say so in the report. CHANGELOG `### Changed` (severity changes affect gates). Commit `fix(registry): consistent encryption-at-rest severity, no breach articles on CKV_AWS_288, map CKV2_AWS_27/34 (TEG-11)`.

---

### Iteration close (controller)
- [ ] Final whole-branch review (Opus), one fix wave, scoped re-review.
- [ ] Gate (Haiku), with a fresh image and the recheck harnesses extended with T-13, T-14, T-15, T-17, T-18 and T-19 rows.
- [ ] REVIEW.md "After iteration 3"; TASKS.md; push `version_0.10.0` (no tags).
