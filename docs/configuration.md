# Configuration file

`.tf-eu-guard.yaml` holds scan defaults so CI and developers run the same command.

## Which file is read

Exactly one: `--config FILE` if given (a missing file exits 2), else `.tf-eu-guard.yaml`
in the scan root (the scanned directory, or the parent of a plan file), else none.
Parent directories are never searched, and nothing is discovered with `--checkov-json`
unless `--config` is given. `--no-config` disables both. An explicit `--config` also
disables `.tf-eu-guard-waivers.yaml` discovery; use `waivers:` or `--waivers` to name a file.

`--no-discovery` skips only the discovery: `.tf-eu-guard.yaml` and `.tf-eu-guard-waivers.yaml` in the
scan root are not read (each skipped file is named on stderr), while `--config`, `--waivers` and a
config's `waivers:` key still apply. Use it in CI, where those files are controlled by the pull
request's author; the Python API has `no_discovery=True`.

## Precedence

CLI flag > config file > built-in default. `exclude`, `registry_dirs` and `var_files` are lists: the
config entries come first, then the CLI ones. A config boolean can only turn a gate on;
there is no `--no-fail-on-any`. `waivers`, `registry_dirs` and `var_files` paths are relative to the
config file's directory.

## Keys

All optional; an unknown key, a bad value, duplicate keys, invalid YAML or a non-mapping
root exits 2.

| Key | Type | Flag |
| --- | --- | --- |
| `iac_type` | string | `--iac-type` |
| `framework` | string | `--framework` |
| `residency_policy` | string | `--residency-policy` |
| `allowed_regions` | list of strings | `--allowed-regions` |
| `exclude` | list of strings | `--exclude` |
| `fail_on_severity` | string | `--fail-on-severity` |
| `fail_on_any`, `fail_on_suppressed`, `fail_on_unmapped` | boolean (`true`/`false`, not `"yes"`) | gate flags |
| `timeout` | number | `--timeout` |
| `max_waiver_days` | integer, at least 1 | `--max-waiver-days` |
| `waivers` | path string | `--waivers` |
| `registry_dirs` | list of path strings | `--registry-dir` |
| `var_files` | list of path strings | `--var-file` |
| `severity_overrides` | map of check ID to severity | none |

```yaml
fail_on_severity: high
exclude: [tests/fixtures]
waivers: .tf-eu-guard-waivers.yaml
severity_overrides:
  CKV_AWS_16: MEDIUM   # accepted risk, documented in the ADR
```

The residency rules still apply to merged values (`custom` needs `allowed_regions`, and
`allowed_regions` needs `custom`).

## Severity overrides

Applied to mapped findings (active, suppressed, waived, passed) after the registry loads
and before gating. Severities are case-insensitive. An override for a check ID that is not
in the registry prints a warning on stderr and is ignored.

## Scan settings that reduce findings

Each of these is listed in the dev terminal header, the three HTML headers, JSON
`scan.weakening_settings` and SARIF `run.properties.weakeningSettings`, whether it came
from the config or the CLI: `config:`, `exclude:`, `waivers:` (with entry count),
`severity override:`, `registry overlay:`, `baseline:` and `changed-since:`. `--output csv` and the legacy JSON array (stdout stays pure) print the same list as a
stderr block. Nothing is printed when the list is empty.
