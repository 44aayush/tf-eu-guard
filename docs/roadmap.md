# Roadmap

Shipped features are listed first, then planned work. Planned items carry no
promised dates or order. Detailed designs for them live in the maintainer's
working notes (`NEW_FUNC.md`); the descriptions here are the short form.

## Shipped

### Mapping and checks

- NIS2 Article 21 and GDPR Article 32 mapping, with a requirement-level
  coverage inventory ([`regulatory-coverage.md`](regulatory-coverage.md))
- AWS, Azure and GCP Terraform registries
- Kubernetes support: a manifest-directory scan with its own registry and
  custom checks
- Terraform plan mode (`terraform show -json` files)
- Custom `EUGUARD_*` checks for gaps Checkov does not cover, including
  provider- and resource-level region residency checks

### Reports and CI

- Dev (terminal and HTML), security and auditor reports
- SARIF 2.1.0 for GitHub Code Scanning, with rule help, tags, severity scores
  and fingerprints
- Severity and finding gates for CI, a GitHub Action, and a pre-commit hook
- Container image with provenance and SBOM attestations

### 0.8.0

- Suppression reporting: inline `checkov:skip` comments appear in every report
  with their reason, and `--fail-on-suppressed` can gate on them
- Configurable residency policy (`--residency-policy`, `--allowed-regions`),
  with `eu-eea` as the new default
- Versioned JSON object format (`--json-format object`, schema in
  `tests/schemas/report.schema.json`); the array format is deprecated
- `--exclude` / `--skip-path`, `--allow-partial`, and `--online` for Checkov
- Checks on `--checkov-json` input (parsing errors, version mismatch, missing
  custom checks)
- Offline-by-default scans (Checkov runs with `--skip-download`), a hardened
  Action container, and hash-checked dependency locks
- More AWS regions and a drift check against botocore

### 0.8.1

- OCI image labels link the GHCR package to the repository

## Planned

No dates are promised. The IDs refer to `NEW_FUNC.md`.

### Trust and adoption

- Waiver file with owner, reason and expiry, and a "Waived" report section (N-01)
- Project configuration file (N-02)
- Custom and overlay registries (N-03)
- Baseline and changed-only mode (N-05)
- List unmapped findings and gate on them (N-13)

### Compliance depth

- Full compliance matrix with passed-check evidence (N-04)
- Residency engine for Azure, GCP and plan mode, with adequacy-decision
  classification (N-06)
- More regulatory frameworks: Implementing Regulation (EU) 2024/2690, ENISA
  guidance, DORA technical controls, ISO/IEC 27001 Annex A, BSI C5, national
  NIS2 profiles (N-07). Earlier notes listed ISO 27001 and NIST CSF; NIST CSF is
  not currently planned.
- Registry growth and tooling, including `explain` and a per-mapping confidence
  field (N-08)
- Evidence bundle with provenance (N-15)
- Scope GDPR findings by data classification (N-19)

### Inputs and integrations

- More IaC inputs: Helm, Kustomize, CloudFormation, ARM and Bicep, Dockerfiles,
  GitHub Actions workflows (N-09)
- Secret scanning through Checkov's secrets framework (N-10)
- CI integrations: job summary, pull-request comment, outputs (N-11)
- Terraform variable files and external modules (N-14)

### Output and API

- More output formats (N-12)
- Versioned JSON schema and a diff command (N-16)
- Registry published in other tools' formats (N-17)
- Stable Python API (N-18)
- Report localisation (N-20)

CRA and DORA remain out of scope as product frameworks, as stated in the
README; DORA's technical controls appear above only as a mapping layer.
