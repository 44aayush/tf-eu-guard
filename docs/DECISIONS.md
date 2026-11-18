# Architecture & Design Decisions

Key technical decisions behind tf-eu-guard, taken from the project's
implementation history.

## 1. Wrap Checkov; don't reimplement scanning

Checkov (pinned at 3.4.5 for reproducible scans) provides detection; tf-eu-guard
adds the compliance layer: parsing Checkov's JSON, joining each failed check to
the NIS2/GDPR registry entry, and rendering reports. Pre-generated Checkov JSON
can also be piped in (`--checkov-json`), so existing Checkov CI jobs work
unchanged.

## 2. Severity is authored in the registry

Checkov 3.x emits `severity: null` for most checks. tf-eu-guard therefore
assigns each mapping a severity (CRITICAL/HIGH/MEDIUM/LOW) in the registry,
weighted by regulatory impact.

## 3. Unmapped findings stay visible without invented compliance advice

Findings with no registry mapping are kept in a separate list rather than
silently discarded. The dev, security, and auditor reports show an unmapped
count and caveat; JSON keeps its mapped-findings-only contract and writes the
unmapped count to stderr; SARIF includes each unmapped result with its Checkov
identity, resource, and location. Unmapped SARIF rules/results carry
`properties.mapped: false` and no registry-authored severity, articles, or
remediation. An empty mapped result means "no mapped compliance
gaps", and says nothing about whether Checkov found anything.

## 4. Article citations are verified against the legal text

NIS2 Art. 21(2) sub-point letters and GDPR Art. 32(1) letters are checked
against Directive (EU) 2022/2555 and Regulation (EU) 2016/679 directly (see
`docs/nis2-mapping.md` and `docs/gdpr-mapping.md`). Notable corrections:
access control is Art. 21(2)(i) (not (e)); encryption is Art. 21(2)(h) /
GDPR 32(1)(a); known third-country transfer review maps to GDPR Chapter V
(Art. 44), not Art. 32. The separate EUSC-only deployment rule is a project
policy control, not a GDPR citation.

## 5. Custom EU-specific checks for gaps Checkov doesn't cover

`EUGUARD_POLICY_001` (configurable residency policy; `EUGUARD_GDPR_001` is its deprecated alias),
`EUGUARD_GDPR_002` (known third-country regions, GDPR Chapter V review), and
`EUGUARD_NIS2_001` (selected hardcoded secret fields, Art. 21(2)(e) secure
development) load through Checkov's external-check mechanism. Provider
credentials, EC2 user-data, and Lambda environment secrets remain covered by
their mapped stock Checkov checks rather than the custom check.

## 6. Registry partitioned per provider with schema validation

`tf_eu_guard/mapping/registry-{aws,azure,gcp}.yaml` are glob-loaded and merged
at runtime, with every entry validated against the mapping schema (required
fields, severity enum, framework enum) in CI and in the test suite.

## 7. Scope is NIS2 + GDPR only

CRA (product lifecycle) and DORA (financial-sector operational resilience) are
out of scope — neither maps naturally onto cloud infrastructure configuration
checks.

## 8. Kubernetes gets its own registry file

**Decision (2026-09):** `CKV_K8S_*` check IDs live in a dedicated
`registry-kubernetes.yaml` rather than folding into the provider files. The
K8s namespace has zero ID overlap with the AWS/Azure/GCP-keyed registries,
so a separate file costs nothing and shows the net-new mapping work
(the largest single chunk) on its own. `loader.py` glob-loads
`registry-*.yaml` with a duplicate-key guard, so no loader change was needed.

## 9. Provider-region checks are Terraform-only by design

**Decision (2026-09):** the provider-region checks for EUSC sovereignty and
GDPR Chapter V review apply only to Terraform targets. Kubernetes manifests are
cloud-agnostic: a manifest doesn't declare where the cluster runs, and region
context lives at the cluster/cloud-provider level (node labels,
`topology.kubernetes.io/region`), not per-resource in the manifest. Any
in-manifest heuristic would be easy to bypass and mostly noise.

**What to do instead:** enforce data residency for Kubernetes at the cluster
boundary — cluster placement policy, cloud-provider constraints (e.g. an SCP
denying cluster creation in non-EU regions), or admission policy on
node-selector labels for the rare topology-pinned workload.

**Consequence:** the README's scope table claims GDPR Art. 44 coverage for
Terraform only through `EUGUARD_GDPR_002`; the separate `EUGUARD_GDPR_001`
sovereignty policy is not presented as a GDPR transfer citation. The
Kubernetes gap is documented, not left implicit.

## 10. EUGUARD_GDPR_001 accepts only EU Sovereign Cloud regions

**Decision (2026-09):** the project is based on the AWS European Sovereign
Cloud, so the residency check's allowlist contains only EUSC region codes
(`eusc-de-east-1` — verified against botocore's `aws-eusc` partition data).
Commercial EU regions (`eu-central-1` Frankfurt et al.) fail
`EUGUARD_GDPR_001` even though GDPR's geographic baseline would permit them.
The check is a sovereignty *policy gate* stricter than the legal baseline, and the
finding text says so instead of claiming a violation. They do not receive a
GDPR Chapter V citation. A separate `EUGUARD_GDPR_002` check flags known
regions outside the EU/EEA (for example `us-east-1`) with a hedged Art. 44
review signal; it does not decide whether a transfer occurs or is lawful. This
decision superseded an earlier fix that had widened the allowlist to all
EU/EEA regions (after replacing the original `eu-` prefix match, which wrongly
passed `eu-west-2` London and `eu-central-2` Zurich — GDPR third countries).

**Consequence:** stacks pinned to commercial EU regions now fail the
compliance gate; `examples/compliant-aws` pins its providers to
`eusc-de-east-1`. Fail-closed semantics apply: unresolved region variables
and unrecognized region strings also fail. When AWS launches a second EUSC
region, add it to `EUSC_REGIONS` in
`tf_eu_guard/regions.py` (the tables moved there in 0.8.0).

## 10a. Residency policy is configurable (supersedes the EUSC-only default)

**Decision (2026-11):** `--residency-policy {eu-eea,eusc,custom}` (default
`eu-eea`) with `--allowed-regions` for `custom`. The check was renamed
`EUGUARD_POLICY_001` (it is a policy finding, not a GDPR claim) and
`EUGUARD_GDPR_001` stays for one release as a deprecated alias so 0.7.x
`--checkov-json` files still map. `EUGUARD_POLICY_002` / `EUGUARD_GDPR_003`
add resource-level coverage (`region` argument, replicas, copy destinations).
The previous EUSC-only behaviour is `--residency-policy eusc`.

## 11. Reports are stdlib-built, self-contained HTML; the auditor report never claims a pass

**Decision:** the security and auditor HTML reports are generated with the
standard library (`html` for escaping) into a single file with embedded CSS, no
JavaScript and no external assets. There is no template engine, so the
generator has no template-loading or packaging surface and the output can be
attached to a ticket or opened offline. The auditor report is built only from
*failed* Checkov checks that map to a control, so every article it shows has
open findings. It never states that a control passes: the absence of a finding
is explicitly not evidence of compliance (see
[`limitations.md`](limitations.md)). Showing passed-check evidence is a
planned feature ([`roadmap.md`](roadmap.md)), not current behaviour.
