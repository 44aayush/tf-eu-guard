# tf-eu-guard — tests

All testing is consolidated here. There are two layers:

| Layer | File(s) | Runs Checkov? | Purpose |
|-------|---------|:-------------:|---------|
| **Unit** (hermetic) | `test_registry.py`, `test_mapping.py`, `test_checkov_runner.py` | no | Fast pytest checks: registry integrity, enrichment logic, Checkov-output parsing. |
| **Integration** (single runner) | `run_all_tests.sh` | yes | End-to-end: real CLI, a live Checkov scan of `vulnerable_tf/`, enrichment, all report formats, framework filters, then the unit suite. |

`conftest.py` holds shared fixtures (`registry`, `sample_finding`, paths) and puts
the repo root on `sys.path` so tests import `tf_eu_guard` without an install.

## Quick start

One-time environment setup (creates `venv/`, installs the package **and** dev
extras, runs an initial Checkov scan):

```bash
bash install_and_test.sh
```

Then run the full consolidated suite:

```bash
bash tests/run_all_tests.sh
```

Scan a different Terraform directory:

```bash
TF_TARGET=path/to/terraform bash tests/run_all_tests.sh
```

Unit tests only (fast, no Checkov required):

```bash
pytest tests -o addopts="-q"      # -o addopts neutralises the --cov default
pytest tests                       # with coverage (needs the .[dev] extras)
```

## Where the output goes

`run_all_tests.sh` mirrors everything to `tests/results/` (git-ignored):

- `latest-run.txt` — full transcript of the most recent run (overwritten).
- `run-<timestamp>.txt` — an archived copy of each run.
- `scan.json` — the raw Checkov JSON from that run, kept for inspection.

This is deliberate: the suite is meant to be run by a human and the transcript
reviewed afterwards.

## How results are classified

The runner never uses `set -e`; each test reports independently:

- **PASS** — assertion succeeded.
- **FAIL** — a real problem; listed in the summary and sets a non-zero exit code.
- **SKIP** — a prerequisite is missing (e.g. the `checkov` CLI isn't installed).
  When Checkov is absent, the runner falls back to `tests/fixtures/checkov-vulnerable-tf.json`
  so enrichment can still be exercised.
- **WARN** — a known limitation. The `security` and `auditor` output formats are
  still stubs in `cli.py` (they print `[Not implemented]`), so they are reported
  as WARN rather than FAIL until they are wired up.

## Phase 2 coverage

- `test_registry.py` — registry loads; ≥ 20 mappings; every entry has a
  check_name / risk / remediation / severity and ≥ 1 well-formed article; and
  the legal-citation corrections are guarded (access control → NIS2 Art. 21(2)(i);
  encryption → NIS2 Art. 21(2)(h) + GDPR Art. 32(1)(a)).
- `test_mapping.py` — `enrich_findings` keeps only registry-mapped findings,
  attaches the registry's articles/risk/remediation/severity, and preserves
  Checkov's own `check_name`; `split_findings` additionally returns the
  unmapped findings so the CLI can surface them (they are never silently
  dropped).

## Later additions

- `test_cli.py` — argparse wiring, framework filters, exit-code gating, and the
  unmapped-findings contract (json stderr note, report counts, gating policy).
- `test_precommit_hook.py` — the shipped `.pre-commit-hooks.yaml`
  (`pass_filenames: false`) and a real `pre-commit run --all-files` against
  vulnerable/compliant fixture repos (skipped when pre-commit isn't installed).
- `test_hook_smoke_dispatch.py` / `test_smoke_check.py` — the tools/ regression
  guard itself: routing table, baseline comparisons, exit codes.
- `test_doc_counts.py` — documented mapping counts match the registries.

## Legacy cleanup

The old scattered scripts (`test_phase1.sh`, `quick_test.sh`,
`MANUAL_TESTING_INSTRUCTIONS.md`, `test_checkov_output.py`) are superseded by
this directory. Remove them with:

```bash
bash tests/cleanup_legacy_files.sh
```

It removes only that explicit list (git-aware), and logs to `tests/results/`.
`install_and_test.sh` and `tests/fixtures/checkov-vulnerable-tf.json` are intentionally kept.
