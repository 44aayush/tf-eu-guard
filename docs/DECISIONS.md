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
