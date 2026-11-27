# tools/

Developer tooling. Not part of the installed package.

## Regression guards

| Script | Purpose |
|--------|---------|
| `smoke_check.py` | Scan each vulnerable/compliant example pair and verify the mapped-finding counts against `smoke_baselines.json`. Exit 0 = counts OK, 2 = a count is outside its baseline (the silent-0 guard), 1 = unexpected error. Usage: `python3 tools/smoke_check.py --iac-type terraform` |
| `smoke_baselines.json` | Expected mapped-finding counts per IaC type — the single source of truth read by CI, `smoke_check.py`, and the Claude Code hook. |
| `hook_smoke_dispatch.py` | PostToolUse hook dispatcher for Claude Code (`.claude/settings.json`): maps an edited file path to the IaC types it can affect and runs only those smoke checks. Exits 2 to surface a failed check. |
| `check_doc_counts.py` | Verify every mapping count in README/CONTRIBUTING/docs against the registry files, so hand-typed counts can't drift. Usage: `python3 tools/check_doc_counts.py` (exit 1 on mismatch) |
| `check_cloud_region_tables.py` | Offline check that the Azure and GCP tables in `tf_eu_guard/regions.py` match the reviewed snapshots in `tools/region_snapshots/` (`azure.json`, `gcp.json`). Usage: `python3 tools/check_cloud_region_tables.py` (exit 1 on drift, 2 if a snapshot cannot be loaded). Runs in the CI `test` job. |
| `generate_checkov_coverage.py` | Generate `docs/checkov-coverage.md`: every check of the installed Checkov (Terraform resource, data, module, provider and graph checks, Kubernetes) as mapped, intentionally unmapped (reasons in `checkov_triage.yaml`) or untriaged. `--check` exits 1 when the doc is stale, when a registry ID is absent from this Checkov release, or when an ID is both mapped and triaged as unmapped; untriaged checks are never an error. Needs Checkov installed. Runs in the CI `test` job. **A Checkov bump changes the catalogue: re-run `python3 tools/generate_checkov_coverage.py` and commit the doc.** |

**Refreshing a region snapshot.** The check cannot see the providers' pages; a person has to. Open the snapshot's `source` URL (Azure: Microsoft Learn regions list; GCP: Google Cloud regions and zones), compare it with the `eu_eea`, `third_country` and `unclassified` lists, update `tf_eu_guard/regions.py` and the snapshot together (keep lists sorted; `unclassified` holds codes that are known but deliberately not in the tables, such as Azure `finlandcentral`/`greececentral` and GCP dual-region `eur4`), set `verified` to the date you checked, and run the tool. A classification table is not a legal conclusion; leave a code unclassified when unsure.

See [CONTRIBUTING.md](../CONTRIBUTING.md) §"Smoke checks" for the workflow.

## Demo artifact generation

| Script | Purpose |
|--------|---------|
| `ansi_to_image.py` | Render a captured ANSI terminal session to SVG (via `rich`) and PNG (via Playwright headless Chromium). Usage: `venv/bin/python tools/ansi_to_image.py <capture.ansi> <out.png> [title] [max_lines]` |
| `make_cast.py` | Convert an ANSI capture into an asciinema v2 `.cast` recording with realistic typing/output pacing. Usage: `venv/bin/python tools/make_cast.py <capture.ansi> <out.cast> [command]` |

Typical regeneration flow for the README screenshots and demo cast:

```bash
source venv/bin/activate
FORCE_COLOR=1 COLUMNS=110 tf-eu-guard scan examples/vulnerable-aws/ --output dev > /tmp/v.ansi
python tools/ansi_to_image.py /tmp/v.ansi docs/screenshots/vulnerable-scan.png "tf-eu-guard — vulnerable-aws" 55
python tools/make_cast.py /tmp/v.ansi docs/demo/tf-eu-guard-demo.cast
```

Requires `playwright` + its Chromium build (`pip install playwright && playwright install chromium`).
