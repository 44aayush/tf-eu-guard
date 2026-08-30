---
name: tf-eu-guard
description: Scan Terraform/IaC for EU compliance gaps (NIS2 + GDPR) using the tf-eu-guard CLI, which wraps Checkov and maps each finding to specific NIS2 Art. 21(2) and GDPR Art. 32 articles. Use when the user asks to check Terraform for NIS2, GDPR, or EU compliance, map a Checkov scan to EU regulations, or produce a compliance report for infrastructure-as-code.
---

# tf-eu-guard — EU compliance scan for Terraform

`tf-eu-guard` runs Checkov against Terraform, keeps only the findings that map to an EU
compliance article, and enriches each with its **NIS2 Art. 21(2)** / **GDPR Art. 32** (and
44–49) reference, a plain-language risk, remediation, and a severity.

## When to use
- The user asks to check Terraform / IaC for **NIS2**, **GDPR**, or "EU compliance".
- The user has a Checkov JSON result and wants it mapped to EU regulatory requirements.
- The user wants a compliance report (terminal, HTML, or JSON) for a Terraform stack.

## Prerequisites
Run from the repo root. Install once (this also installs Checkov 3.3.13; requires Python ≥ 3.10):

```bash
pip install -e .
```

Verify with `tf-eu-guard version` (should print a version string).

## How to run

**Mode 1 — scan a Terraform directory** (tf-eu-guard runs Checkov itself):

```bash
tf-eu-guard scan <terraform-dir> --output json --framework all
```

**Mode 2 — reuse a Checkov JSON the user already has** (no re-scan):

```bash
# from a file
tf-eu-guard scan --checkov-json <file.json> --output json

# or piped from a fresh Checkov run (use '-' for stdin)
checkov -d <terraform-dir> --output json --framework terraform --quiet \
  | tf-eu-guard scan --checkov-json - --output json
```

Flags:
- `--output` — `dev` (Rich terminal), `json` (machine-readable), `security` (HTML dashboard
  with severity breakdown), `auditor` (HTML article-by-article compliance matrix), or `all`
  (writes the dev, security, and auditor HTML reports together). For a compliance review,
  recommend `--output auditor`; for full coverage, `--output all`.
- `--framework` — `nis2`, `gdpr`, or `all` (default). Filters to findings citing that framework.
- `--fail-on-severity {CRITICAL,HIGH,MEDIUM,LOW}` / `--fail-on-any` — exit code 1 when
  findings meet the threshold (CI/CD gating).

Prefer `--output json` when you (Claude) will parse and summarize the result. HTML reports are
written to `reports/` (or `--output-dir`); mention the file paths to the user so they can open them.

## Interpreting the output
Each finding has `check_id`, `severity` (CRITICAL/HIGH/MEDIUM), `resource`, `file_path`, and one
or more `articles` (`{framework, article}`). Checkov findings with **no** EU mapping are dropped
by design, so an empty result means "no *mapped* compliance gaps", not "no Checkov findings".

When reporting back to the user:
1. Give counts by severity and by framework (NIS2 vs GDPR).
2. List the top findings (resource + file + the article each violates).
3. For remediation detail, point to `docs/nis2-mapping.md` and `docs/gdpr-mapping.md`.

## Notes
- The compliance mappings live in `tf_eu_guard/mapping/registry.yaml`.
- `examples/vulnerable-aws/` (and the broader `examples/end2end/` suite) are intentionally-insecure stacks you can use to demo the tool.
- If Bash permission prompts are noisy, the user can allow `Bash(tf-eu-guard scan:*)` and
  `Bash(checkov:*)` in `.claude/settings.local.json`.
