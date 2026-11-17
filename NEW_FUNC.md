# NEW_FUNC — functionality worth adding to tf-eu-guard

Part of the [0.7.1 review](REVIEW.md). Defects and fixes are listed separately in [TASKS.md](TASKS.md); a `T-nn` reference below points there.

Each item gives what to build, why it matters, and a starting design. Value and effort are my estimates, not measurements.

## Summary

| ID | Feature | Value | Effort | Depends on |
| --- | --- | --- | --- | --- |
| N-01 | Waiver file and suppression reporting | High | Medium | T-01 |
| N-02 | Project configuration file | High | Medium | |
| N-03 | Custom and overlay registries | High | Small | |
| N-04 | Full compliance matrix with passed-check evidence | High | Medium | |
| N-05 | Baseline and changed-only mode | High | Medium | |
| N-06 | Residency engine for Azure, GCP, plan mode and adequacy decisions | High | Large | T-06, T-07 |
| N-07 | More regulatory frameworks | High | Large | N-03 |
| N-08 | Registry growth and registry tooling | High | Ongoing | |
| N-09 | More IaC inputs | Medium | Medium | |
| N-10 | Secret scanning through Checkov's secrets framework | Medium | Small | T-04, T-05 |
| N-11 | CI integrations: job summary, pull-request comment, outputs | Medium | Medium | T-16 |
| N-12 | More output formats | Medium | Medium | N-16 |
| N-13 | List unmapped findings and gate on them | Medium | Small | |
| N-14 | Terraform inputs: variable files and external modules | Medium | Small | T-12 |
| N-15 | Evidence bundle with provenance | Medium | Medium | N-04 |
| N-16 | Versioned JSON schema, and a diff command | Medium | Medium | T-14 |
| N-17 | Publish the registry in other tools' formats | Medium | Medium | |
| N-18 | Stable Python API | Low | Small | |
| N-19 | Scope GDPR findings by data classification | Low | Medium | N-02 |
| N-20 | Report localisation | Low | Medium | |

If only three are built, build N-01, N-02 and N-04. The first two remove the main obstacles to adopting the tool on an existing codebase. The third is what makes the auditor report useful as evidence.

---

## Trust and adoption

### N-01 · Waiver file and suppression reporting

- **What**: A reviewed file, for example `.tf-eu-guard-waivers.yaml`, that lists accepted findings by check ID and resource, each with an owner, a reason and an expiry date. Reports get a "Waived" section. Expired waivers become findings again. Inline `checkov:skip` comments are reported, and can be made to fail with `--fail-on-suppressed`.
- **Why**: Today the only way to accept a finding is an inline comment, which makes it disappear without trace (T-01). Auditors expect accepted risks to be listed with a justification and a review date. The project already applies exactly this discipline to its own dependency advisories in `dependency-exceptions.json`.
- **Sketch**: Reuse the shape of `dependency-exceptions.json`. Match on check ID plus resource address, with an optional file glob. Emit SARIF `suppressions` for waived results.

### N-02 · Project configuration file

- **What**: `.tf-eu-guard.yaml` or a `[tool.tf-eu-guard]` table, read from the scan root or passed with `--config`. Settings: residency policy and allowed regions, excluded paths, default IaC type and framework, gate threshold, severity overrides, variable files, waiver file location.
- **Why**: Every option is currently a command-line flag, and several needed ones do not exist (T-06, T-11). The pre-commit hook and the Action then need no per-repository argument lists.
- **Sketch**: Decide who may change it. In CI the file comes from the scanned checkout, so settings that weaken the result (excludes, waivers, thresholds) should be printed in the report header, and the Action should offer an input that pins the config to a trusted path.

### N-03 · Custom and overlay registries

- **What**: `--registry-dir` to add or override mappings, with later files winning per check ID, and a report line stating which overlays were loaded.
- **Why**: 181 of roughly 700 AWS checks are mapped, and 23 Azure and 22 GCP. Organisations will want to map more, change a severity, or add an internal policy framework without forking. `load_registry` already accepts a directory; `registry_path` is only a test hook today.
- **Sketch**: Allow extra framework names in overlays. Keep the four bundled namespaces mandatory. Add `tf-eu-guard registry validate <dir>`.

### N-05 · Baseline and changed-only mode

- **What**: `--baseline findings.json` so that only findings absent from the baseline affect the gate, and a mode that reports only findings in files changed against a Git reference.
- **Why**: A first scan of a real estate returns dozens of HIGH findings. Without a baseline the gate is either off or permanently red.
- **Sketch**: Identify a finding by check ID, resource address and file, not by line number. Print the baseline's age in the report.

### N-13 · List unmapped findings and gate on them

- **What**: `--show-unmapped` to list unmapped Checkov failures in the terminal and HTML reports, and `--fail-on-unmapped`.
- **Why**: Only SARIF shows which checks were unmapped. The other formats give a count and tell the user to run Checkov again.

---

## Compliance depth

### N-04 · Full compliance matrix with passed-check evidence

- **What**: Keep Checkov's passed checks and show, for all fifteen inventoried requirements, how many mapped checks ran, passed, failed and were suppressed, beside the coverage label (automated, partial, manual). Requirements with no evaluated check say so.
- **Why**: The auditor report lists only articles with failures. It cannot distinguish "the relevant controls were checked and passed" from "nothing relevant was scanned". The coverage model in `tf_eu_guard/mapping/coverage.py` already exists and is used only to generate documentation.
- **Sketch**: Extend extraction to `passed_checks`. Present counts, not a single score, and keep the existing statement that an absent finding is not evidence of compliance.

### N-06 · Residency engine for Azure, GCP, plan mode and adequacy decisions

- **What**: (a) Azure `location` and GCP `region`/`location` checks. (b) Residency evaluation of plan JSON by reading the provider configuration and resource values directly, since Checkov's plan runner does not run provider checks. (c) Classification by transfer basis: EU/EEA, adequacy decision under GDPR Art. 45, or other third country.
- **Why**: The residency checks are the tool's most distinctive feature and currently cover AWS provider blocks in source mode only. The tool advertises Azure and GCP mappings but has no residency check for either. Plan mode is described as showing what will actually be applied, yet it is the mode with no residency check. The United Kingdom, Switzerland, Japan, South Korea, Israel and New Zealand have adequacy decisions, so reporting their regions under Art. 44 at HIGH with the same wording as any other third country overstates the issue.
- **Sketch**: Keep region-to-country and country-to-status as dated data files with the date last checked, and print that date in reports. The adequacy list changes, and some decisions cover only part of a country's recipients.

### N-07 · More regulatory frameworks

- **What**: Additional mappings, delivered as registries or overlays:
  - Commission Implementing Regulation (EU) 2024/2690, which sets detailed NIS2 technical requirements for cloud, data-centre, managed-service and similar providers.
  - ENISA's NIS2 technical implementation guidance (version 1.0, June 2025), which includes a mapping table to other standards.
  - DORA, through the technical controls in its regulatory technical standards on ICT risk management.
  - ISO/IEC 27001:2022 Annex A and BSI C5, which many EU auditors work from.
  - National NIS2 transposition profiles.
- **Why**: Mapping to Art. 21(2) letters is coarse; eight of the ten letters carry every NIS2 mapping. Auditors of in-scope providers work from the Implementing Regulation. The README excludes DORA because it is not about cloud configuration, but its technical standards require encryption, network security and logging controls that the existing checks already evidence.
- **Sketch**: Add a cross-walk layer, check to control to framework clause, so one curated control list serves several frameworks. Verify clause numbers against the published texts before release.

### N-08 · Registry growth and registry tooling

- **What**: A report of the most frequently failing unmapped checks across the example suites; `tf-eu-guard explain <check-id>`; a per-mapping confidence field (direct, partial, indirect) shown in reports; Azure and GCP coverage brought closer to AWS.
- **Why**: The registry is the product. Some mappings are loose, for example liveness probes and CPU limits mapped to NIS2 Art. 21(2)(c) on business continuity and backup. `docs/limitations.md` already describes confidence levels in prose; putting them in the data lets a reader filter by them.
- **Sketch**: Have the registry reviewed once by someone with legal or audit standing and record the review in the repository. This would add more credibility than any feature.

### N-15 · Evidence bundle with provenance

- **What**: Each report records tool version, Checkov version, a hash of the loaded registries, the scanned commit, the exact options, and counts of resources and checks evaluated. An option writes all reports plus a manifest of their hashes.
- **Why**: A report offered as audit evidence has to show what was scanned, with which rules, and that it has not been edited.
- **Sketch**: In CI, attest the bundle with GitHub artifact attestations.

### N-19 · Scope GDPR findings by data classification

- **What**: Let a resource tag or a config rule state whether a resource holds personal data, and apply GDPR mappings only where it does or where it is unknown.
- **Why**: `docs/limitations.md` states that personal data is assumed present everywhere. That is safe but produces GDPR citations for resources that hold none.

---

## Inputs

### N-09 · More IaC inputs

- **What**: Helm charts, Kustomize, CloudFormation, ARM and Bicep, Dockerfiles and GitHub Actions workflows, all of which Checkov already scans. Allow several types in one run with a merged report.
- **Why**: Kubernetes users mostly ship Helm or Kustomize, not raw manifests. Workflow and Dockerfile checks are supply-chain evidence for NIS2 Art. 21(2)(d), which has only six mappings.
- **Sketch**: Each type needs its own registry file. OpenTofu and Terragrunt need documentation more than code.

### N-10 · Secret scanning through Checkov's secrets framework

- **What**: Optionally run Checkov's `secrets` framework and map its findings to NIS2 Art. 21(2)(e) and GDPR Art. 32(1)(b).
- **Why**: The two custom secret checks cover five AWS resource types, CodeBuild and Kubernetes, with name-based heuristics (T-04, T-05). A pattern- and entropy-based scanner covers Azure, GCP and arbitrary files without new code.

### N-14 · Terraform inputs: variable files and external modules

- **What**: `--var-file` (repeatable) and an opt-in `--download-external-modules`.
- **Why**: A region or password supplied through a `.tfvars` file is unresolved today, which produces a false finding (T-06). Resources inside registry modules are not scanned at all (T-12). The runner currently strips the corresponding Checkov environment variables without offering a replacement.
- **Sketch**: Downloading modules fetches third-party code, so keep it off by default and incompatible with the no-network container setting in T-15.

---

## Outputs and integrations

### N-11 · CI integrations: job summary, pull-request comment, outputs

- **What**: A Markdown summary written to the GitHub job summary; an optional pull-request comment with new findings; Action outputs for counts by severity; an `artifact-name` input; a GitLab CI template.
- **Why**: With the default `output: json`, the Action's only visible result is raw JSON in the log.

### N-12 · More output formats

- **What**: Markdown; CSV for auditors' spreadsheets; JUnit XML; GitLab code-quality and SAST reports; OSCAL assessment results. Print styles so the HTML reports export cleanly to PDF.
- **Why**: Auditors and non-GitHub pipelines cannot consume SARIF or the current HTML easily.

### N-16 · Versioned JSON schema, and a diff command

- **What**: A JSON object with `schema_version`, tool and Checkov versions, scan target, and full findings (line range, check name, risk, remediation, articles) plus unmapped, suppressed and waived lists. Publish the JSON Schema. Add `tf-eu-guard diff old.json new.json`.
- **Why**: The current array cannot grow without breaking consumers (T-14). A diff gives trend reporting and powers N-05.

### N-17 · Publish the registry in other tools' formats

- **What**: Generate from the registry a Trivy compliance specification, and labels or bundles for OPA and Kyverno policy sets.
- **Why**: Trivy and Kubescape already accept custom compliance frameworks, so the most likely way this project gets displaced is someone publishing a NIS2 specification for one of them. Publishing it here keeps the registry as the reference and reaches users who will not add a second scanner.
- **Sketch**: This needs a check-ID cross-walk between Checkov and the target tool, which is the main cost.

### N-18 · Stable Python API

- **What**: A documented `scan()` function returning a typed result, and a `py.typed` marker.
- **Why**: The package is fully type-annotated and passes mypy, but exposes only the CLI. `ScanReport` in `tf_eu_guard/models.py` is an unused start on this.

### N-20 · Report localisation

- **What**: German and French versions of the report text and article titles.
- **Why**: Auditors under national NIS2 laws often work in the national language. Low priority until the English content is stable.
