# tf-eu-guard — tests

All testing is consolidated here as a hermetic pytest suite (`test_*.py`). It
does not run Checkov except in tests that opt in with `TFEG_RUN_CHECKOV=1`
(CI sets it). CI (`.github/workflows/ci.yml`) additionally scans the `examples/`
fixtures end to end and `action-e2e.yml` exercises the GitHub Action itself.

`conftest.py` holds shared fixtures (`registry`, `sample_finding`, paths) and puts
the repo root on `sys.path` so tests import `tf_eu_guard` without an install.

## Quick start

One-time environment setup (creates `venv/`, installs the package and dev
extras, runs an initial Checkov scan):

```bash
bash install_and_test.sh
```

Then run the suite:

```bash
pytest tests -o addopts="-q"      # -o addopts neutralises the --cov default
pytest tests                       # with coverage (needs the .[dev] extras)
TFEG_RUN_CHECKOV=1 pytest          # include the tests that run real Checkov
```

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
- `test_coverage_model.py` — generated requirement-level coverage matches the
  live registries and the committed `docs/regulatory-coverage.md`.
- `test_python_support.py` — the supported-Python-version floor stays in sync
  across pyproject (`requires-python` + classifiers), the CI matrix, the README
  badge, and `install_and_test.sh`.
- `test_reports.py` — hermetic dev/security/auditor HTML structure, rendered
  findings, escaping, stable ordering, and unmapped-count caveats.
- `test_cli.py` — end-to-end HTML output, timestamped report files, custom
  destinations, and unmapped findings across report formats.
- `test_action.py` — Action HTML artifact selection and SARIF destination
  wiring.

## Checkov capture fixtures

The committed `tests/fixtures/checkov-*.json` files retain their
`summary.checkov_version` value of **3.3.13** as historical parser and
enrichment captures. They are deliberately not current-runtime claims. Live
source scans and the package dependency use pinned Checkov **3.4.5**; the
capture version is preserved so parser regressions remain reproducible.
