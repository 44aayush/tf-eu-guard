# Architecture

How a tf-eu-guard scan actually works: what runs, in what order, and
where the compliance layer sits relative to Checkov. This complements
[`DECISIONS.md`](DECISIONS.md) (which records *why* the key choices were
made). This document is the *how*, and describes the code in
`tf_eu_guard/` as it is.

## The one-sentence version

tf-eu-guard runs Checkov against your infrastructure code, joins every
**failed** check to a curated NIS2/GDPR mapping registry entry, and
renders the enriched findings as developer, security, auditor, JSON, and SARIF
reports. Checkov detects; the registry and the reports are what tf-eu-guard adds.

## Pipeline

```
target ─▶ 1. run_checkov() ─▶ 2. extract_failed_checks() ─▶ 3. load_registry()
             (or load_checkov_json())                          │
                                                              ▼
                                                  4. split_findings()
                                                     ├─ enriched (mapped)
                                                     └─ unmapped (surfaced)
                                                              │
                                                              ▼
                                                  5. filter: --framework
                                                              │
                                                              ▼
                                                  6. report: dev / json /
                                                     security / auditor / SARIF
                                                              │
                                                              ▼
                                                  7. gate: --fail-on-*
                                                     → exit code 0/1
```

### 1. Obtain Checkov results — `tf_eu_guard/checkov_runner.py` and `tf_eu_guard/checkov/`

Two entry paths, same output shape:

- `run_checkov(path, iac_type)` shells out to Checkov 3.4.5 (pinned in
  `pyproject.toml` for reproducible scans). `iac_type` maps to
  Checkov's `--framework`: `terraform` (directory of source),
  `terraform_plan` (a `terraform show -json` file, via `checkov -f`), or
  `kubernetes` (manifests directory).
- `load_checkov_json(file_or_stdin, iac_type)` accepts Checkov JSON you
  already generated — including the multi-check-type array Checkov emits
  without a single `--framework` — so an existing Checkov CI job can
  pipe its output straight in (`--checkov-json -`).

### 2. Filter to failures — `extract_failed_checks()`

(Checkov's `skipped_checks`, which carry inline `checkov:skip` suppressions, are
read in the same pass and shown by every report as suppressed findings; they do
not count as active findings. See `tf_eu_guard/reporting/suppressed.py`.)

Checkov reports passed *and* failed checks; only failures become
findings. Each finding carries the identity the registry joins on:
`check_id`, resource address, file path, and line range. Plan-mode
findings report `[0, 0]` because a plan file is one JSON line — reports
detect this and omit the line reference rather than printing a bogus
"line 0".

### 3. Load the registry — `tf_eu_guard/mapping/loader.py`

All `registry-*.yaml` files in `tf_eu_guard/mapping/` (AWS, Azure, GCP,
Kubernetes, split by check-ID namespace and merged at runtime) are
glob-loaded. The four expected namespace files must all be present and
non-empty; missing or empty registry data raises `RegistryValidationError`.
Every entry is schema-validated on load (required fields,
severity/framework enums, duplicate-key guard); the CLI exits 3. The
registry ships with the tool, so this is a runtime failure, not a mistake in your
invocation.

### 4. Enrich and split — `split_findings()`

This is the join step. Findings with
a registry mapping get severity (authored in the registry — Checkov
emits `severity: null` for most checks), the NIS2/GDPR article
citations, a risk explanation, and copy-paste remediation. Findings
with no mapping go to a separate *unmapped* list. HTML and terminal reports
surface its count, JSON writes the count to stderr, and SARIF retains the
Checkov identity/resource/location with `properties.mapped: false` but no
registry-authored severity, articles, or remediation. Unmapped findings never
gate a build: they stay visible without claiming regulatory authority (see
[`limitations.md`](limitations.md)).

### 5. Filter — `--framework nis2|gdpr`

Post-enrichment filter on the article's framework. Unrelated to
`--iac-type` (what gets scanned); this selects which regulatory regime
to *report*. `all` also retains project-policy controls such as region
residency-policy findings; those controls are not included in a GDPR-only filter.

### 6. Report — `tf_eu_guard/reporting/`

One scan, five formats (plus `all`): `dev` (terminal table, severity
sorted), `json` (pure mapped-findings array on stdout, unmapped count on
stderr), `sarif` (SARIF 2.1.0 for GitHub Code Scanning, including mapped and
unmapped results), `security` and `auditor` (HTML; the auditor report is
article-by-article for audit preparation). All formats use the same mapped
findings list, with the unmapped list surfaced according to each format's
contract.

### 7. Gate — `tf_eu_guard/cli/gating.py`

`--fail-on-severity` / `--fail-on-any` set exit code 1 when mapped
active findings meet the threshold (unmapped findings count only when `--unmapped-severity` sets a severity for them); `--fail-on-suppressed` sets it when any
mapped finding was suppressed by an inline Checkov comment. The other exit codes are documented in the
README's CI/CD Gating section: 0 clean, 1 findings, 2 invalid
input/configuration, 3 scanner/runtime failure. A pipeline can then fail
the build on findings and page someone different when the tool
itself is broken.

## Module layout

| Path | Role |
| --- | --- |
| `tf_eu_guard/cli/` | Command line: `parser.py` (arguments), `pipeline.py` (obtain results, filter), `reports.py` (format dispatch), `gating.py` (exit-code gates), `paths.py`, `errors.py` (exception to exit code), `app.py` (orchestration), `__main__.py` |
| `tf_eu_guard/checkov_runner.py` | Compatibility facade that re-exports the names below for older callers |
| `tf_eu_guard/checkov/process.py` | Checkov subprocess, scrubbed environment, scan-root and symlink validation |
| `tf_eu_guard/checkov/json.py` | Validation and normalisation of Checkov JSON (`load_checkov_json`, failed and skipped checks) |
| `tf_eu_guard/checkov/types.py` | `CheckovRuntimeError`, `CheckovInputError` |
| `tf_eu_guard/residency.py` | Residency policy selection (`eu-eea`, `eusc`, `custom`). The CLI passes the policy to the Checkov subprocess through two environment variables; the custom checks read it with `allowed_regions_from_env()` |
| `tf_eu_guard/regions.py` | AWS region tables (EUSC, EU/EEA, known third-country) shared by the policy and the checks |
| `tf_eu_guard/checks/` | Custom `EUGUARD_*` Checkov checks: `gdpr/data_residency.py` (AWS: provider-level `EUGUARD_POLICY_001`, `EUGUARD_GDPR_002`, resource-level `EUGUARD_POLICY_002`, `EUGUARD_GDPR_003`), `gdpr/azure_residency.py` (Azure: `EUGUARD_POLICY_003`, `EUGUARD_GDPR_004`), `gdpr/gcp_residency.py` (GCP: `EUGUARD_POLICY_004`, `EUGUARD_GDPR_005`), `nis2/` (secrets in code), `k8s/` (Kubernetes secrets) |
| `tf_eu_guard/checks/regions_conf.py` | Collects the regions a Terraform resource configuration names (the `region` argument, replicas, copy destinations) for the resource-level checks `EUGUARD_POLICY_002` and `EUGUARD_GDPR_003` |
| `tf_eu_guard/checks/values.py` | Helpers for reading Checkov's nested-list attribute values |
| `tf_eu_guard/mapping/` | Registry YAML per provider, `loader.py`, `schema.py`, `enrichment.py` (the join), `requirements.py` and `coverage.py` (requirement inventory and coverage labels) |
| `tf_eu_guard/models.py` | `EnrichedFinding`, `ScanReport` and the severity and framework enums |
| `tf_eu_guard/reporting/` | One reporter per format. `suppressed.py` flattens findings suppressed by inline `checkov:skip` comments (mapped and unmapped) into one ordered record type that every report renders; `html_common.py`, `sorting.py` and `styles.py` are shared by the HTML reports |

## Checkov as a swappable detection backend

The compliance layer never parses Terraform or Kubernetes directly.
Step 1 is the only place Checkov is invoked, and steps 2–7 operate on
its JSON, so the backend can be swapped:

- The registry keys on Checkov's check IDs, so a different detection
  engine would need new IDs and a registry remap, but not a new pipeline.
- `--checkov-json` already exercises the seam: it feeds step 2 from
  Checkov output produced outside this process, so steps 3–7 already run
  on raw JSON without Checkov present.
- Custom `EUGUARD_*` checks load *through* Checkov's external-check
  mechanism rather than a parallel scanner, so tool-specific
  detection keeps a single result shape.

The cost of the pin is that the Checkov version in `pyproject.toml` is held fixed so registry IDs
reproduce scan-to-scan. A backend upgrade is therefore a deliberate,
registry-reviewed change.

### Source-root symlink boundary

Before a source-directory scan, the runner resolves all symlinked files and
directories under the requested root. Links that resolve outside that root, or
broken links, are rejected with exit code `2`; links that resolve inside the
root are allowed and their targets are scanned. Resolved directories are
visited once, so in-root directory cycles do not recurse indefinitely. This
boundary applies to Terraform and Kubernetes directory scans, not to a single
Terraform plan file.

## Where the numbers come from

Every count in the docs (mappings per provider, per-requirement
coverage) is generated from the registry files — `tools/
check_doc_counts.py` for raw counts, `tools/generate_coverage_doc.py`
for the requirement-level classification (`docs/
regulatory-coverage.md`). Both run in CI with drift checks, the same
way the smoke baselines in `tools/smoke_baselines.json` pin expected
finding counts per example.
