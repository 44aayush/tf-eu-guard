---
name: tf-eu-guard
description: Scan Terraform (source, plan JSON) and Kubernetes IaC for EU compliance gaps (NIS2 + GDPR) using the tf-eu-guard CLI, which wraps Checkov and maps each finding to specific NIS2 Art. 21(2) and GDPR Art. 32 articles. Use when the user asks to check Terraform or Kubernetes for NIS2, GDPR, or EU compliance, map a Checkov scan to EU regulations, or produce a compliance report for infrastructure-as-code.
---

# tf-eu-guard — EU compliance scan for IaC

`tf-eu-guard` runs Checkov against Terraform (source or plan JSON) or Kubernetes
manifests, keeps only the findings that map to an EU compliance article, and enriches
each with its **NIS2 Art. 21(2)** / **GDPR Art. 32** (and 44–49) reference, a
plain-language risk, remediation, and a severity.

## When to use
- The user asks to check Terraform or Kubernetes / IaC for **NIS2**, **GDPR**, or "EU compliance".
- The user has a Checkov JSON result and wants it mapped to EU regulatory requirements.
- The user wants a compliance report (terminal, HTML, or JSON) for an IaC stack.

## Prerequisites
Run from the repo root. Install once (this also installs Checkov 3.3.13; requires Python ≥ 3.10):

```bash
pip install -e .
```

Verify with `tf-eu-guard version` (should print a version string).

## How to run

**Mode 1 — scan an IaC directory** (tf-eu-guard runs Checkov itself):

```bash
tf-eu-guard scan <terraform-dir> --output json --framework all
tf-eu-guard scan <k8s-dir> --iac-type kubernetes --output json
```

**Mode 2 — scan a Terraform plan JSON** (the `terraform show -json` output of a saved plan):

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
tf-eu-guard scan --checkov-json plan.json --iac-type terraform_plan --output json
```

**Mode 3 — reuse a Checkov JSON the user already has** (no re-scan):

```bash
# from a file
tf-eu-guard scan --checkov-json <file.json> --output json

# or piped from a fresh Checkov run (use '-' for stdin)
checkov -d <terraform-dir> --output json --framework terraform --quiet \
  | tf-eu-guard scan --checkov-json - --output json
```

Flags:
- `--iac-type` — `terraform` (default), `terraform_plan`, or `kubernetes`. **What to scan.**
  `terraform_plan` requires `--checkov-json` (a plan JSON is a single file, not a directory).
- `--framework` — `nis2`, `gdpr`, or `all` (default). **Which compliance regime to report.**
  Unrelated to `--iac-type` despite the similar name.
- `--output` — `dev` (Rich terminal), `json` (machine-readable), `security` (HTML dashboard
  with severity breakdown), `auditor` (HTML article-by-article compliance matrix), or `all`
  (writes the dev, security, and auditor HTML reports together). For a compliance review,
  recommend `--output auditor`; for full coverage, `--output all`.
- `--fail-on-severity {CRITICAL,HIGH,MEDIUM,LOW}` / `--fail-on-any` — exit code 1 when
  findings meet the threshold (CI/CD gating).

Prefer `--output json` when you (Claude) will parse and summarize the result. HTML reports are
written to `reports/` (or `--output-dir`); mention the file paths to the user so they can open them.

## Interpreting the output
Each finding has `check_id`, `severity` (CRITICAL/HIGH/MEDIUM), `resource`, `file_path`, and one
or more `articles` (`{framework, article}`). Checkov findings with **no** EU mapping are dropped
by design, so an empty result means "no *mapped* compliance gaps", not "no Checkov findings".

Resource and line formats differ by `--iac-type`:
- Terraform source: `aws_s3_bucket.data` addresses with real line ranges.
- Terraform plan: Terraform addresses but `file_line_range` is `[0, 0]` — reports omit
  the line reference rather than print a meaningless `0-0`.
- Kubernetes: `Kind.namespace.name` identifiers (e.g. `Pod.app-ns.app`).

When reporting back to the user:
1. Give counts by severity and by framework (NIS2 vs GDPR).
2. List the top findings (resource + file + the article each violates).
3. For remediation detail, point to `docs/nis2-mapping.md` and `docs/gdpr-mapping.md`.

## Notes
- The compliance mappings live in `tf_eu_guard/mapping/`, split per namespace: `registry-aws.yaml`
  (covers Terraform source *and* plan), `registry-azure.yaml`, `registry-gcp.yaml`, and
  `registry-kubernetes.yaml` (the `CKV_K8S_*` namespace).
- `examples/vulnerable-aws/` (and the broader `examples/end2end/` suite) and
  `examples/vulnerable-kubernetes/` are intentionally-insecure stacks you can use to demo the
  tool. `examples/vulnerable-aws-plan/plan.json` is a committed plan-JSON fixture.
- GDPR Art. 44 (data residency) coverage is Terraform-only; Kubernetes manifests are
  cloud-agnostic and region is a cluster-level concern (see `docs/DECISIONS.md`).
- If Bash permission prompts are noisy, the user can allow `Bash(tf-eu-guard scan:*)` and
  `Bash(checkov:*)` in `.claude/settings.local.json`.
