---
name: tf-eu-guard
description: Scan Terraform (source, plan JSON) and Kubernetes IaC for EU compliance gaps (NIS2 + GDPR) using the tf-eu-guard CLI, which wraps Checkov and maps each finding to specific NIS2 Art. 21(2) and GDPR Art. 32 articles. Use when the user asks to check Terraform or Kubernetes for NIS2, GDPR, or EU compliance, map a Checkov scan to EU regulations, or produce a compliance report for infrastructure-as-code.
---

# tf-eu-guard — EU compliance scan for IaC

`tf-eu-guard` runs Checkov against Terraform (source or plan JSON) or Kubernetes
manifests and enriches every finding with its **NIS2 Art. 21(2)** / **GDPR
Art. 32** (and 44) reference, a plain-language risk, remediation, and a
severity. Findings with no EU mapping are **not discarded** — they're tracked
separately and reported as an unmapped count (see "Interpreting the output").

## When to use
- The user asks to check Terraform or Kubernetes / IaC for **NIS2**, **GDPR**, or "EU compliance".
- The user has a Checkov JSON result and wants it mapped to EU regulatory requirements.
- The user wants a compliance report (terminal, HTML, JSON, or SARIF) for an IaC stack.

## Prerequisites
Run from the repo root. Install once (this also installs Checkov 3.3.13; requires Python ≥ 3.11):

```bash
pip install -e .
```

Verify with `tf-eu-guard version` (prints e.g. `tf-eu-guard 0.4.1`).

## How to run

**Mode 1 — scan an IaC directory** (tf-eu-guard runs Checkov itself):

```bash
tf-eu-guard scan <terraform-dir> --output json --framework all
tf-eu-guard scan <k8s-dir> --iac-type kubernetes --output json
```

If `path` is omitted, it defaults to the current directory (this is what lets
the bundled pre-commit hook invoke the CLI with no positional argument).

**Mode 2 — scan a Terraform plan JSON** (the `terraform show -json` output of a saved plan):

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
tf-eu-guard scan plan.json --iac-type terraform_plan --output json
```

**Mode 3 — reuse a Checkov JSON the user already has** (no re-scan — Checkov
*output* JSON, not a raw Terraform plan file):

```bash
# from a file
tf-eu-guard scan --checkov-json <file.json> --output json

# or piped from a fresh Checkov run (use '-' for stdin)
checkov -d <terraform-dir> --output json --framework terraform --quiet \
  | tf-eu-guard scan --checkov-json - --output json
```

Flags:
- `--iac-type` — `terraform` (default), `terraform_plan`, or `kubernetes`. **What to scan.**
  `terraform_plan` scans a plan file: pass its path as PATH. `--checkov-json` expects
  Checkov *output* JSON only — a raw `terraform show -json` plan there is an error.
- `--framework` — `nis2`, `gdpr`, or `all` (default). **Which compliance regime to report.**
  Unrelated to `--iac-type` despite the similar name.
- `--output` — `dev` (Rich terminal, default), `json` (mapped findings only — see below),
  `sarif` (SARIF 2.1.0, includes **both** mapped and unmapped findings, each tagged with a
  `properties.mapped` boolean and full remediation text), `security` (HTML dashboard with
  severity breakdown and unmapped count), `auditor` (HTML article-by-article compliance
  matrix), or `all` (writes the dev, security, and auditor HTML reports together).
  For a compliance review, recommend `--output auditor`; for full coverage including
  unmapped findings in a parseable format, recommend `--output sarif` over `--output json`.
- `--output-file FILE` — for `--output security|auditor|sarif`, write the single report
  here instead of the default filename (`sarif` defaults to stdout). Ignored for `dev`,
  `json`, and `all`.
- `--output-dir DIR` — directory for HTML report output (default: `reports/`). For
  `--output all`, all three HTML files land here with timestamped names.
- `--fail-on-severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}` / `--fail-on-any` — exit code 1 when
  a **mapped** finding meets the threshold (CI/CD gating). Unmapped findings never trip
  the gate — they have no registry-authored severity to compare, so they're reported for
  visibility only. Empty value disables gating.

Prefer `--output sarif` (not `--output json`) when you (Claude) need the complete picture,
including unmapped findings, in a format you'll parse. Use `--output json` only when you
specifically want mapped findings alone. HTML reports are written to `reports/` (or
`--output-dir`/`--output-file`); mention the file paths to the user so they can open them.

## Interpreting the output
Each finding has `check_id`, `severity` (CRITICAL/HIGH/MEDIUM/LOW), `resource`, `file_path`,
and one or more `articles` (`{framework, article}`).

**`--output json` returns mapped findings only** — a Checkov finding with no registry entry
is silently absent from this array specifically. It is *not* absent from the scan: `dev` and
`security` output show an "Unmapped Checkov findings: N" count, and `--output sarif` includes
every unmapped finding as a full result with `properties.mapped: false`. If you only ever
call `--output json`, you will not see that count — say so if you report a scan as "clean"
based on JSON output alone, since a JSON-based "0 findings" can still mean real unmapped
Checkov findings exist.

Resource and line formats differ by `--iac-type`:
- Terraform source: `aws_s3_bucket.data` addresses with real line ranges.
- Terraform plan: Terraform addresses but `file_line_range` is `[0, 0]` — reports omit
  the line reference rather than print a meaningless `0-0`.
- Kubernetes: `Kind.namespace.name` identifiers (e.g. `Pod.app-ns.app`).

When reporting back to the user:
1. Give counts by severity and by framework (NIS2 vs GDPR), and the unmapped count if you have it (`dev`/`security`/`sarif` output, not plain `json`).
2. List the top findings (resource + file + the article each violates).
3. For remediation detail, point to `docs/nis2-mapping.md` and `docs/gdpr-mapping.md`.

## Notes
- The compliance mappings live in `tf_eu_guard/mapping/`, split per namespace: `registry-aws.yaml`
  (covers Terraform source *and* plan), `registry-azure.yaml`, `registry-gcp.yaml`, and
  `registry-kubernetes.yaml` (the `CKV_K8S_*` namespace).
- `examples/vulnerable-aws/` (and the broader `examples/end2end/` suite), `examples/vulnerable-kubernetes/`,
  and `examples/unmapped-aws/` (deliberately includes findings with no registry mapping, useful
  for demonstrating the unmapped-count behavior above) are intentionally-insecure stacks for
  demoing the tool. `examples/vulnerable-aws-plan/plan.json` is a committed plan-JSON fixture.
- GDPR Art. 44 (data residency) only recognizes the AWS European Sovereign Cloud
  (`eusc-*` regions) as compliant — commercial EU regions like `eu-central-1` are flagged
  for review, not treated as automatically compliant. Kubernetes has no equivalent check;
  manifests are cloud-agnostic and region is a cluster-level concern (see `docs/DECISIONS.md`).
- A GitHub Action (`action.yml`) and a pre-commit hook (`.pre-commit-hooks.yaml`) both wrap
  this CLI for CI/CD use — point users there instead of hand-rolling a workflow step.
- If Bash permission prompts are noisy, the user can allow `Bash(tf-eu-guard scan:*)` and
  `Bash(checkov:*)` in `.claude/settings.local.json`.
