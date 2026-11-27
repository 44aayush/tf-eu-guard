# Limitations & Honest Scope

What tf-eu-guard can and cannot tell you, consolidated in one place.
The same points appear in narrower form throughout
[`gdpr-mapping.md`](gdpr-mapping.md),
[`nis2-mapping.md`](nis2-mapping.md) and the reports themselves. This
document is where to send anyone who needs the full picture, especially
an auditor or security reviewer evaluating whether the tool's output
counts as evidence.

## Technical evidence, not legal determination

tf-eu-guard verifies infrastructure configuration. A clean scan is
technical evidence that the mapped controls are configured correctly,
but it does not make you NIS2- or GDPR-compliant. Both
frameworks are judged on organizational measures, processes and
documentation that no configuration linter can inspect; the
requirement-level classification in
[`regulatory-coverage.md`](regulatory-coverage.md) exists so
this is visible per-requirement rather than implied.

## Mapping confidence varies by article

Not all mappings carry the same weight:

- **High confidence**: the requirement names the control explicitly
  (e.g. GDPR Art. 32(1)(a) encryption; NIS2 Art. 21(2)(h) cryptography
  and encryption). A finding here is close to a direct citation.
- **Partial**: the requirement spans technical and organisational
  halves, and only the technical slice is evaluable from IaC (e.g.
  Art. 21(2)(b): logging is visible; alerting, triage and response
  playbooks are not). The mapped checks speak to the slice, and
  passing them says nothing about the other half.
- **Process-as-evidence**: some requirements are evidenced by *running
  this tool* (NIS2 Art. 21(2)(f), GDPR Art. 32(1)(d)): a repeatable,
  timestamped CI assessment. That is one component of the requirement,
  not the whole of it — pen tests, DPIAs and review cadence remain
  outside.

Per-check evidence and limitations for each article are in
[`gdpr-mapping.md`](gdpr-mapping.md) and
[`nis2-mapping.md`](nis2-mapping.md); the full check-level matrix is
[`check-mapping-table.md`](check-mapping-table.md).

## What the checks cannot see

Recurring structural blind spots (each also noted in the article docs):

- **Backup ≠ restore.** Checks confirm backups/versioning are
  *enabled*, not that a restore works within an RTO.
- **Logging ≠ monitoring.** Logging configuration is visible; alerting,
  triage and on-call process are not.
- **Access control is configuration-only.** Who the principals actually
  are, and what they do with their access, is outside IaC.
- **MFA and identity-provider state** live at the account/IdP level,
  not per-resource — a resource linter has limited visibility there.
- **Region checks are signals, not verdicts.** A commercial EU region can
  fail a stricter configured residency policy (for example `--residency-policy
  eusc`) without being a GDPR Chapter V transfer. A known non-EU/EEA region is flagged for Chapter V
  review; adequacy decisions, SCCs and BCRs can lawfully permit a transfer,
  and the tool cannot see transfers made by application code or downstream
  services. Kubernetes is out of scope for residency entirely — manifests
  don't declare where the cluster runs (see [`DECISIONS.md`](DECISIONS.md) #9).
  Residency checks read literal values: a region supplied by a variable fails
  the policy checks closed (pass non-default variable files with `--var-file`; `terraform.tfvars` and `*.auto.tfvars` are loaded automatically), S3 replication
  destinations are not evaluated, `--checkov-json` cannot apply a policy
  (results are pre-computed), and plan-mode residency is not
  covered. Azure residency (`EUGUARD_POLICY_003`, `EUGUARD_GDPR_004`) reads the literal `location` of
  `azurerm_*` resources against a maintained table; a newer EU location not yet in the table fails the
  policy check until it is added, `location = "global"` (for example on `azurerm_monitor_action_group`) also fails
  `EUGUARD_POLICY_003` (use a regional location where the resource allows one, or add a waiver), and `--residency-policy eusc` (an AWS partition) uses the Azure EU/EEA table.
  GCP residency (`EUGUARD_POLICY_004`, `EUGUARD_GDPR_005`) reads the literal `region` of `provider "google"` blocks and
  the `region`, `location` and `zone` of `google_*` resources (a zone maps to its region) against a maintained
  table; a dual-region such as `EUR4` or a newer EU region not yet in the table fails the policy check until it is
  added, `location = "global"` (for example on `google_kms_key_ring`) also fails `EUGUARD_POLICY_004`, and
  `--residency-policy eusc` uses the GCP EU/EEA table. The `google-beta` provider block is not evaluated.
  GCP coverage gaps: the provider block's `zone` argument is not checked, nested placement settings (such as
  `custom_placement_config.data_locations`, Secret Manager replica locations and Spanner instance configs) are not
  evaluated, and multi-regions such as `europe` fail `EUGUARD_POLICY_004` because they are not on the allowlist.

## Unmapped findings

Only findings with an honest compliance link get a mapping; the rest
are deliberately unmapped (methodology in
[`check-mapping-table.md`](check-mapping-table.md)). They are surfaced as a
count in terminal/HTML reports and as a stderr count beside JSON; SARIF also
preserves each unmapped identity, resource, and location with
`properties.mapped: false` but no registry remediation. They never gate a
build. Their absence from the compliance view reflects mapping coverage and says
nothing about their security relevance. A scan that shows "53
mapped, 9 unmapped" is reporting 62 real Checkov failures, not 53.

## Inline suppressions

Checkov honours inline skip comments: `#checkov:skip=CKV_AWS_18:reason` in
Terraform and `checkov.io/skip1: CKV_K8S_8=reason` annotations in Kubernetes.
Checkov moves such results from `failed_checks` to `skipped_checks`, and
anyone who can edit the scanned code can add them. tf-eu-guard therefore
reads `skipped_checks` and never lets a suppression disappear:

- Every report lists suppressed checks separately ("Suppressed by inline
  comment") with check ID, resource, file and lines, and the stated reason
  (or "no reason given" when the comment has none or Checkov's
  "No comment provided" placeholder).
- Suppressed findings are not active findings: they are excluded from the
  totals, severity counts and article tables, and they do **not** count toward
  `--fail-on-severity` / `--fail-on-any`. A scan whose only failures were
  suppressed is reported as "No active findings; N suppressed", never as a
  clean result.
- `--fail-on-suppressed` exits 1 when any *mapped* suppressed finding exists
  (unmapped ones never gate, as with the other gates). `--framework` filters
  suppressed findings exactly as it filters active ones, so the gate follows
  the selected framework.
- JSON entries carry `"suppressed"` and `"suppression_reason"` (`false`/`null`
  for active findings). Unmapped suppressed checks are, like unmapped active
  ones, only counted on stderr in JSON. SARIF results get
  `suppressions: [{"kind": "inSource", "justification": <reason>}]`
  (`justification` is omitted when no reason was given), for mapped and
  unmapped checks alike.

What this does not do: it does not verify that a stated reason is true or
approved, and it does not expire suppressions. Without `--fail-on-suppressed`
a suppression is visible but does not fail the build; a reviewed waiver file
with owners and expiry dates (`--waivers`, see `docs/waivers.md`) is how to
accept a finding with a recorded justification.
Suppressions made outside the scanned code (for example a
`.checkov.yml` skip list) are blocked by the runner, not reported.

## Network access and platform mode

By default tf-eu-guard runs Checkov with `--skip-download`: Checkov makes
no request to the Prisma Cloud platform, so scans work offline and give the
same result everywhere. The cost is that findings from a source scan carry
no "Documentation" link (the guideline URL is platform metadata); reports
omit the link rather than failing. `--online` removes `--skip-download` and
lets Checkov fetch that metadata (one HTTPS request per scan).

Platform credentials are never forwarded. Only an allowlist of variables
reaches Checkov (`PATH`, `HOME`, `USER`, locale `LANG`/`LC_*`, `TZ`, temp
directories, proxy and CA-bundle variables, the Windows essentials such as
`SYSTEMROOT`, and the XDG cache/config directories), with or without
`--online`. Every other variable, including `BC_API_KEY`, `PRISMA_API_URL`,
`BC_CA_BUNDLE`, `CKV_*`, `CHECKOV_*`, `GIT_*` and `CKV_IGNORED_DIRECTORIES`, is
dropped, so Checkov cannot enter platform mode, upload results or apply
suppressions configured on the platform.

## Scan scope: skipped paths and `--exclude`

Checkov does not read hidden entries (names starting with `.`),
`.terraform`, `node_modules` or `.serverless`. A directory scan warns on stderr when a hidden
directory (other than tooling ones such as `.git` or `.github`) holds source files; pass it as the
scan path to scan it. Likewise, when AWS resources are scanned but no `provider "aws"` block sets a
region, a warning says the residency checks could not evaluate a region; scan a Terraform plan instead. The pre-scan guards (symlink
containment and the `*.tf.json` rejection) skip the same entries, so a
virtual environment's `bin/python` link or a Terraform plugin cache does not
abort a scan. Elsewhere, a symlink that leaves the scan root or is broken
aborts the scan (exit 2) when it is a directory or a file Checkov would
parse for the selected IaC type (`.tf`, `.tfvars`, `.hcl` for Terraform;
`.yaml`, `.yml`, `.json` for Kubernetes); any other such link only prints a
warning. `--exclude PATTERN` (repeatable, alias `--skip-path`) is passed to
Checkov as `--skip-path` and applied by the guards with the same matching:
a regular expression searched in the absolute path (a pattern starting with
a single `.` is taken literally), or a plain substring of it. Example:
`tf-eu-guard scan . --exclude tests/fixtures`.

## Remote modules are not analysed

Checkov does not download registry or Git modules, so resources defined
inside a module whose `source` is not a local path (`./` or `../`) are never
evaluated: a call such as `terraform-aws-modules/s3-bucket/aws` with
`acl = "public-read"` yields no finding for that bucket. After a Terraform
source scan tf-eu-guard prints a stderr warning, "not analysed: remote
module sources", listing each such module call. The module-pinning checks
`CKV_TF_1` (commit hash) and `CKV_TF_2` (version tag) run on the call itself
and are mapped to NIS2 Art. 21(2)(d), supply chain security. Scan a
`terraform show -json` plan (`--iac-type terraform_plan`) to cover module
contents, because a plan contains the expanded resources. Alternatively,
`--download-external-modules` lets Checkov fetch the modules (Terraform source
scans only). That needs network access and runs third-party module code through
the parser, and tf-eu-guard prints a stderr note when it is used. With the flag,
the module-download credentials (`TF_REGISTRY_TOKEN`, `TFC_TOKEN`, `TF_HOST_NAME`,
`GITHUB_PAT`, `VCS_*`, `BITBUCKET_*`, `SSH_AUTH_SOCK`, and Checkov's own proxy settings
`PROXY_URL`, `PROXY_CA_PATH`, `PROXY_HEADER_KEY`, `PROXY_HEADER_VALUE`) also reach Checkov; without it
they do not. `CHECKOV_TERRAFORM_ALLOWED_MODULE_PREFIXES` and `VCS_ALLOWED_HOSTS`
are always passed on, because they only restrict downloads. The GitHub
Action runs with `--network none`, so the flag does not work there. Variables
set only in a `.tfvars` file other than `terraform.tfvars` or `*.auto.tfvars` are
unresolved unless the file is passed with `--var-file FILE`.

## Assumptions worth knowing about

- **Personal data is assumed present.** GDPR Art. 32 governs the
  security of *personal-data* processing; the tool cannot know which
  resources hold personal data, so it takes the conservative
  assumption that the scanned infrastructure does.
- **Severity is authored, not detected.** Checkov 3.4.5 emits
  `severity: null` for most checks, so severities come from the
  registry, weighted by regulatory impact. Two people could defensibly
  disagree with a given rating, which is why the registry is versioned and
  reviewable.
- **Checkov 3.4.5 is pinned.** Check IDs (the registry's join keys)
  are stable within that pin; upgrading the backend is a deliberate,
  registry-reviewed event.

## NIS2 is a directive, not a single rulebook

Directive (EU) 2022/2555 sets the floor; each member state transposes
it into national law, and supervisory expectations, deadlines and
enforcement differ between them. tf-eu-guard maps against the
directive's Article 21(2) text — national implementations may add or
shape requirements beyond what is mapped here. The tool is useful
across the EU, but it is not a per-jurisdiction compliance verdict.

## Out of scope entirely

CRA (product lifecycle) and DORA (financial-sector operational
resilience) regulate other things than cloud-infrastructure
configuration. GDPR obligations beyond security of processing
(lawful basis Art. 6, data-subject rights Arts. 12–23, records of
processing Art. 30, DPIA Art. 35) are likewise not evaluable from IaC
and are not claimed.

## Waivers live in the scanned checkout

A waiver file found in the scanned checkout (`.tf-eu-guard-waivers.yaml`) can be edited
by whoever can edit the code, so it is a convenience for reviewed acceptances and is not
tamper-proof. Every waived finding stays listed in the reports so a reviewer can
see it. In the GitHub Action, use the `trusted-config` input to take settings from a file outside the checkout.

tf-eu-guard runs only `git rev-parse` and `git diff --name-only` (committed/staged), with fsmonitor and hooks disabled, and never runs commands that compare working-tree file contents, because a hostile repo config can attach commands to those. Provenance therefore records the commit but cannot detect uncommitted changes, and `--changed-since` ignores unstaged changes.
