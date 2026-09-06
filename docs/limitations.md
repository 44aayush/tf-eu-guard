# Limitations & Honest Scope

What tf-eu-guard can and cannot tell you, consolidated in one place.
The same points appear in narrower form throughout
[`gdpr-mapping.md`](gdpr-mapping.md),
[`nis2-mapping.md`](nis2-mapping.md) and the reports themselves — this
document is where to send anyone who needs the full picture, especially
an auditor or security reviewer evaluating whether the tool's output
counts as evidence.

## Technical evidence, not legal determination

tf-eu-guard verifies **infrastructure configuration**. A clean scan is
technical evidence that the mapped controls are configured correctly —
it is not a determination that you are NIS2- or GDPR-compliant. Both
frameworks are judged on organizational measures, processes and
documentation that no configuration linter can inspect; the
requirement-level classification in
[`regulatory-coverage.md`](regulatory-coverage.md) exists precisely so
this is visible per-requirement rather than implied.

## Mapping confidence varies by article

Not all mappings carry the same weight:

- **High confidence** — the requirement names the control explicitly
  (e.g. GDPR Art. 32(1)(a) encryption; NIS2 Art. 21(2)(h) cryptography
  and encryption). A finding here is close to a direct citation.
- **Partial** — the requirement spans technical and organisational
  halves, and only the technical slice is evaluable from IaC (e.g.
  Art. 21(2)(b): logging is visible; alerting, triage and response
  playbooks are not). The mapped checks speak to the slice, and
  passing them says nothing about the other half.
- **Process-as-evidence** — some requirements are evidenced by *running
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
- **Data residency is a signal, not a verdict.** A non-EU provider
  region is flagged for review; adequacy decisions, SCCs and BCRs can
  lawfully permit the transfer, and the tool cannot see transfers made
  by application code or downstream services. Kubernetes is out of
  scope for residency entirely — manifests don't declare where the
  cluster runs (see [`DECISIONS.md`](DECISIONS.md) #9).

## Unmapped findings

Only findings with an honest compliance link get a mapping; the rest
are deliberately unmapped (methodology in
[`check-mapping-table.md`](check-mapping-table.md)). They are surfaced
as a count in every report format and never gate a build — but their
absence from the compliance view is a statement about *mapping
coverage*, not about their security relevance. A scan that shows "52
mapped, 9 unmapped" is reporting 61 real Checkov failures, not 52.

## Assumptions worth knowing about

- **Personal data is assumed present.** GDPR Art. 32 governs the
  security of *personal-data* processing; the tool cannot know which
  resources hold personal data, so it takes the conservative
  assumption that the scanned infrastructure does.
- **Severity is authored, not detected.** Checkov 3.3.13 emits
  `severity: null` for most checks, so severities come from the
  registry, weighted by regulatory impact. Two people could defensibly
  disagree with a given rating — the registry is versioned and
  reviewable for exactly that reason.
- **Checkov 3.3.13 is pinned.** Check IDs (the registry's join keys)
  are stable within that pin; upgrading the backend is a deliberate,
  registry-reviewed event, not a floating dependency.

## NIS2 is a directive, not a single rulebook

Directive (EU) 2022/2555 sets the floor; each member state transposes
it into national law, and supervisory expectations, deadlines and
enforcement differ between them. tf-eu-guard maps against the
directive's Article 21(2) text — national implementations may add or
shape requirements beyond what is mapped here. The tool is useful
across the EU, but it is not a per-jurisdiction compliance verdict.

## Out of scope entirely

CRA (product lifecycle) and DORA (financial-sector operational
resilience) — different regulatory targets, not cloud-infrastructure
configuration checks. GDPR obligations beyond security of processing
(lawful basis Art. 6, data-subject rights Arts. 12–23, records of
processing Art. 30, DPIA Art. 35) are likewise not evaluable from IaC
and are not claimed.
