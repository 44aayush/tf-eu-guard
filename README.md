# tf-eu-guard

[![CI](https://github.com/44aayush/tf-eu-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/44aayush/tf-eu-guard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Checkov 3.3.13](https://img.shields.io/badge/checkov-3.3.13-8A2BE2)](https://www.checkov.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Mappings](https://img.shields.io/badge/NIS2%20%2B%20GDPR%20mappings-161-orange)](tf_eu_guard/mapping/registry-aws.yaml)

**EU compliance security linter for Terraform** — maps infrastructure misconfigurations to **NIS2** (Directive 2022/2555) and **GDPR** (Regulation 2016/679) requirements.

---

## Problem

The [NIS2 Directive](https://eur-lex.europa.eu/eli/dir/2022/2555) requires covered entities to implement specific cybersecurity measures by October 2024. Article 21(2) mandates risk management measures including access control, encryption, incident handling, backup policies, and secure authentication. GDPR Article 32 imposes similar technical and organizational safeguards for processing personal data.

Most organizations scan infrastructure-as-code with tools like Checkov or tfsec, but **the output is generic security findings** — not compliance mappings. Security teams must manually trace each finding to the relevant NIS2 or GDPR article, a slow and error-prone process that blocks audit preparation.

**tf-eu-guard solves this**: it wraps Checkov, enriches each failed check with the exact NIS2/GDPR articles it violates, and produces reports structured for developers, security engineers, and auditors.

---

## What It Does

1. **Scans Terraform using Checkov** — 1,000+ built-in checks for AWS, Azure, GCP, and other providers
2. **Enriches findings** with NIS2 Article 21(2) and GDPR Article 32(1) / 44 mappings from a curated registry
3. **Filters** to show only EU-compliance-relevant issues (drops unmapped findings)
4. **Generates three report formats** from one scan:
   - **Dev report** (terminal/HTML): severity-sorted findings for engineers
   - **Security dashboard** (HTML): CRITICAL/HIGH/MEDIUM/LOW breakdown with stats
   - **Auditor report** (HTML): article-by-article view showing which NIS2/GDPR clauses have open findings
5. **Custom checks**: Adds EU-specific rules (e.g., non-EU regions, hardcoded secrets) not in upstream Checkov

---

## Quick Start

### Installation

Requires **Python ≥ 3.10**. Installs Checkov 3.3.13 as a dependency.

```bash
pip install tf-eu-guard
```

Also available on PyPI: [tf-eu-guard](https://pypi.org/project/tf-eu-guard/)

For development (from a clone of this repo):

```bash
pip install -e .
```
```

### Basic Scan

```bash
# Scan a Terraform directory
tf-eu-guard scan ./terraform --output dev

# Generate all three HTML reports
tf-eu-guard scan ./terraform --output all

# Filter to GDPR-only findings and output JSON
tf-eu-guard scan ./terraform --output json --framework gdpr

# Fail the build (exit code 1) on HIGH or worse findings — for CI/CD
tf-eu-guard scan ./terraform --fail-on-severity HIGH
```

> **Try it:** Run `tf-eu-guard scan examples/vulnerable-aws/ --output all` to see ~30 mapped findings,
> or `tf-eu-guard scan examples/compliant-aws/ --output dev` to see a clean scan.

### Use Pre-Generated Checkov JSON

If you already run Checkov in CI or with custom checks, feed tf-eu-guard the JSON directly:

```bash
# From a file
checkov -d ./terraform --output json --framework terraform --quiet > checkov.json
tf-eu-guard scan --checkov-json checkov.json --output security

# From stdin
checkov -d ./terraform --output json --framework terraform --quiet \
  | tf-eu-guard scan --checkov-json - --output auditor
```

> Use `--framework terraform` in Checkov to get a single JSON object. tf-eu-guard also handles the multi-check-type array and extracts the `terraform` result automatically.

### Use as a Claude Code Skill

This repo includes a Claude Code skill at `.claude/skills/tf-eu-guard/`. In Claude Code:

```
/tf-eu-guard ./terraform
```

Or just ask: *"Check my Terraform for NIS2 and GDPR compliance"* — Claude runs the scan and summarizes findings by framework and severity.

---

## Usage

### Developer Scan

Quick terminal output for engineers fixing issues:

```bash
tf-eu-guard scan ./terraform --output dev
```

![Dev report terminal output](https://raw.githubusercontent.com/44aayush/tf-eu-guard/main/docs/screenshots/vulnerable-scan.png)

### Security Dashboard

HTML report with severity breakdown and compliance tags:

```bash
tf-eu-guard scan ./terraform --output security
```

![Security dashboard](https://raw.githubusercontent.com/44aayush/tf-eu-guard/main/docs/screenshots/security-dashboard.png)

> Live HTML version: [`docs/screenshots/scan-report.html`](https://github.com/44aayush/tf-eu-guard/blob/main/docs/screenshots/scan-report.html)

### Auditor Compliance Matrix

Article-by-article view for audit preparation:

```bash
tf-eu-guard scan ./terraform --output auditor
```

![Auditor report](https://raw.githubusercontent.com/44aayush/tf-eu-guard/main/docs/screenshots/auditor-report.png)

> Live HTML version: [`docs/screenshots/auditor-report.html`](https://github.com/44aayush/tf-eu-guard/blob/main/docs/screenshots/auditor-report.html)

### JSON (CI/CD & Tooling)

Machine-readable output for pipelines:

```bash
tf-eu-guard scan ./terraform --output json --framework nis2
```

### Generate All Reports at Once

```bash
tf-eu-guard scan ./terraform --output all
```

### CI/CD Gating

Exit codes make tf-eu-guard usable as a pipeline gate. Exit code `1` is returned when findings meet the threshold; `0` otherwise:

```bash
tf-eu-guard scan ./terraform --fail-on-severity HIGH   # fail on HIGH or CRITICAL
tf-eu-guard scan ./terraform --fail-on-any             # fail on any finding
```

### GitHub Action

```yaml
- uses: 44aayush/tf-eu-guard@v1
  with:
    path: './infra'
    fail-on-severity: 'HIGH'
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/44aayush/tf-eu-guard
    rev: v0.1.0
    hooks:
      - id: tf-eu-guard
```

---

## Scope

| Regulation | Coverage | Status |
|------------|----------|--------|
| **NIS2 Article 21(2)** | Technical/organizational cybersecurity measures | ✅ **38 check mappings** |
| **GDPR Article 32(1)** | Security of processing (encryption, access control, resilience) | ✅ **38 check mappings** |
| **GDPR Article 44** | Transfers to third countries (non-EU regions) | ✅ **Custom check** `EUGUARD_GDPR_001` |

> **Note:** CRA and DORA are out of scope for this tool — they address product lifecycle and financial-sector operational resilience respectively, not cloud infrastructure configuration.

### Current Registry

**161 Checkov checks mapped** — **AWS: 116 mappings | Azure: 23 mappings | GCP: 22 mappings** — covering
encryption at rest/in transit, logging & detection, backup & recovery,
secure development/supply chain, secrets in code, IAM/access control, and network
segmentation:

- **IAM / access control**: CKV_AWS_273, 287, 288, 62, 286, 63, 355, 289, 290, 274, 40, 9, 109, 111, 283, 356, 70, 79, 162, 359, CKV2_AWS_40, CKV2_AWS_41, CKV2_AWS_52
- **Encryption (rest + transit)**: CKV_AWS_145, 3, 8, 96, 5, 247, 44, 347, 279, 280, 327, 136, 189, 186, 173, 58, 7, 127, 376, 228, 379, CKV2_AWS_2, CKV2_AWS_64, CKV2_AWS_69
- **Logging / detection**: CKV_AWS_18, 157, 101, 84, 317, 324, 325, 92, 37, 50, 126, 353, 158, 338, CKV2_AWS_11, CKV2_AWS_30, CKV2_AWS_62
- **Backup / resilience**: CKV_AWS_21, 144, 326, 361, 139, 115, 116, 135, 318, 313, 362, CKV2_AWS_8, CKV2_AWS_58, CKV2_AWS_59, CKV2_AWS_60, CKV2_AWS_61
- **Secure development / secrets**: CKV_AWS_226, 363, 272, 51, 163, 41, 45, 46
- **S3 / RDS / network exposure**: CKV_AWS_20, 53–56, 16, 17, 133, 129, 161, 293, 118, 24, 25, 260, 382, 137, 248, 38, 39, 117, 23, CKV2_AWS_6, CKV2_AWS_12, CKV2_AWS_5
- **Custom**: EUGUARD_GDPR_001 (non-EU regions), EUGUARD_NIS2_001 (hardcoded secrets)
- **Azure** (23): `tf_eu_guard/mapping/registry-azure.yaml` — storage account encryption/public access, SQL firewall & public network access, Key Vault network rules, App Service HTTPS/auth/logging, NSG SSH rules, and more
- **GCP** (22): `tf_eu_guard/mapping/registry-gcp.yaml` — GCS bucket CMEK/public IAM, Cloud SQL public IP/SSL/CMEK, GKE private clusters/ABAC/authorized networks, VPC flow logs, and more

The registry is split per provider (`registry-aws.yaml`, `registry-azure.yaml`, `registry-gcp.yaml`) and every entry is schema-validated in CI.

---

## Architecture

```
┌──────────────┐
│  Terraform   │
│    files     │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│  tf-eu-guard                                  │
│  ┌─────────────────────────────────────────┐ │
│  │ 1. run_checkov() / load_checkov_json()  │ │
│  │    → Checkov results (passed + failed)  │ │
│  └──────────────┬──────────────────────────┘ │
│                 ▼                             │
│  ┌─────────────────────────────────────────┐ │
│  │ 2. extract_failed_checks()               │ │
│  │    → Filter to failed checks only        │ │
│  └──────────────┬──────────────────────────┘ │
│                 ▼                             │
│  ┌─────────────────────────────────────────┐ │
│  │ 3. load_registry()                       │ │
│  │    → NIS2/GDPR mapping registry          │ │
│  └──────────────┬──────────────────────────┘ │
│                 ▼                             │
│  ┌─────────────────────────────────────────┐ │
│  │ 4. enrich_findings()                     │ │
│  │    → Join checks ⟷ compliance articles  │ │
│  │    → Drop unmapped findings              │ │
│  └──────────────┬──────────────────────────┘ │
│                 ▼                             │
│  ┌─────────────────────────────────────────┐ │
│  │ 5. Optional: filter by framework         │ │
│  │    (--framework nis2 / gdpr)             │ │
│  └──────────────┬──────────────────────────┘ │
│                 ▼                             │
│  ┌─────────────────────────────────────────┐ │
│  │ 6. generate_report()                     │ │
│  │    → dev / json / security / auditor     │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│  Reports:                                 │
│  • Terminal rich table                    │
│  • dev-report.html                        │
│  • scan-report.html (dashboard)           │
│  • auditor-report.html (by article)       │
│  • JSON (for CI/tooling)                  │
└──────────────────────────────────────────┘
```

**Key differentiator**: The EU compliance mapping registry. Without it, this is just another Checkov wrapper. With it, it's the bridge from "S3 bucket not encrypted" to "violates NIS2 Art. 21(2)(h) and GDPR Art. 32(1)(a)."

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines — especially on proposing new registry mappings. Contributions welcome:

1. **Registry expansion**: Map more Checkov checks to NIS2/GDPR
2. **New custom checks**: EU-specific patterns Checkov doesn't cover
3. **Report improvements**: Better visualizations, export formats

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgments

- **Checkov** ([bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)) — detection engine
- **terragoat** ([bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat)) — vulnerable infrastructure test cases (used in the end-to-end test suite; see [tests/README.md](tests/README.md))
- **NIS2 Directive** — [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555)
- **GDPR** — [Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679)
