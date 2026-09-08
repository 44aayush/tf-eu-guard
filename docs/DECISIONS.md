# Architecture & Design Decisions

Key technical decisions behind tf-eu-guard, extracted from the project's
implementation history.

## 1. Wrap Checkov; don't reimplement scanning

Checkov (pinned at 3.3.13 for reproducible scans) provides detection; tf-eu-guard
adds the compliance layer: parsing Checkov's JSON, joining each failed check to
the NIS2/GDPR registry entry, and rendering reports. Pre-generated Checkov JSON
can also be piped in (`--checkov-json`), so existing Checkov CI jobs work
unchanged.

## 2. Severity is authored in the registry

Checkov 3.3.13 emits `severity: null` for most checks. tf-eu-guard therefore
assigns each mapping a severity (CRITICAL/HIGH/MEDIUM/LOW) in the registry,
weighted by regulatory impact.

## 3. Unmapped findings are dropped by design

Findings with no registry mapping are excluded from reports — the tool's output
is *compliance-relevant* gaps, not raw security noise. An empty result means
"no mapped compliance gaps," not "no Checkov findings."

## 4. Article citations are verified against the legal text

NIS2 Art. 21(2) sub-point letters and GDPR Art. 32(1) letters are checked
against Directive (EU) 2022/2555 and Regulation (EU) 2016/679 directly (see
`docs/nis2-mapping.md` and `docs/gdpr-mapping.md`). Notable corrections:
access control is Art. 21(2)(i) (not (e)); encryption is Art. 21(2)(h) /
GDPR 32(1)(a); data residency maps to GDPR Chapter V (Art. 44), not Art. 32.

## 5. Custom EU-specific checks for gaps Checkov doesn't cover

`EUGUARD_GDPR_001` (non-EU regions, GDPR Chapter V transfers) and
`EUGUARD_NIS2_001` (hardcoded secrets, Art. 21(2)(e) secure development) load
through Checkov's external-check mechanism.

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
so a separate file costs nothing and makes the (largest single chunk of)
net-new mapping work visible on its own. `loader.py` glob-loads
`registry-*.yaml` with a duplicate-key guard, so no loader change was needed.

## 9. EUGUARD_GDPR_001 (data residency) is Terraform-only by design

**Decision (2026-09):** the EU data-residency check (GDPR Chapter V,
Art. 44–49) applies only to Terraform targets. Kubernetes manifests are
cloud-agnostic: a manifest doesn't declare where the cluster runs, and region
context lives at the cluster/cloud-provider level (node labels,
`topology.kubernetes.io/region`), not per-resource in the manifest. Any
in-manifest heuristic would be trivially bypassable and mostly noise.

**What to do instead:** enforce data residency for Kubernetes at the cluster
boundary — cluster placement policy, cloud-provider constraints (e.g. an SCP
denying cluster creation in non-EU regions), or admission policy on
node-selector labels for the rare topology-pinned workload.

**Consequence:** the README's scope table claims GDPR Art. 44 coverage for
Terraform only; the gap is documented rather than silently implied.

## 10. EUGUARD_GDPR_001 accepts only EU Sovereign Cloud regions

**Decision (2026-09):** the project is based on the AWS European Sovereign
Cloud, so the residency check's allowlist contains only EUSC region codes
(`eusc-de-east-1` — verified against botocore's `aws-eusc` partition data).
Commercial EU regions (`eu-central-1` Frankfurt et al.) fail the check even
though GDPR Art. 44 would permit them: this is a sovereignty *policy gate*
stricter than the legal baseline, and finding text says so rather than
claiming a violation. This decision superseded an earlier fix that had
widened the allowlist to all EU/EEA regions (after replacing the original
`eu-` prefix match, which wrongly passed `eu-west-2` London and
`eu-central-2` Zurich — GDPR third countries).

**Consequence:** stacks pinned to commercial EU regions now fail the
compliance gate; `examples/compliant-aws` pins its providers to
`eusc-de-east-1`. Fail-closed semantics apply: unresolved region variables
and unrecognized region strings also fail. When AWS launches a second EUSC
region, add it to `_EUSC_REGIONS` in
`tf_eu_guard/checks/gdpr/data_residency.py`.
