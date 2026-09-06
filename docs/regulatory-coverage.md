# Regulatory Coverage — NIS2 Art. 21(2) & GDPR Art. 32(1)/44

> **Generated file** — rendered by `tools/generate_coverage_doc.py` from the mapping registries and the requirement inventory in `tf_eu_guard/mapping/coverage.py`. Do not edit by hand; CI (via `--check`) fails if this file drifts from the registries.

Coverage here is classified **by requirement, not by mapped-check count**. Every unaddressed requirement otherwise looks identical — silently absent — to a covered one. Four categories:

- ✅ **Automated** — The tool can directly evaluate this from IaC input today.
- ◐ **Partial** — The technical config provides evidence for only part of the requirement; the rest needs non-IaC evidence.
- 👤 **Manual** — Needs non-IaC evidence (policy, governance, staff training, incident-response process) that Terraform/Kubernetes manifests structurally can never show. Listed here so it is visibly *not ignored* — an explicit 'we cannot see this' is more credible than silence.
- ❌ **Not covered** — No current mapping.

**Summary: 15 requirements inventoried — 3 automated · 11 partial · 1 manual.**

## NIS2 — Directive (EU) 2022/2555, Art. 21(2)

| Requirement | Coverage | Mapped checks |
|-------------|----------|---------------|
| **Art. 21(2)(a)** — Risk analysis and information system security | 👤 **Manual** | — |
| **Art. 21(2)(b)** — Incident handling | ◐ **Partial** | **24** |
| **Art. 21(2)(c)** — Business continuity, backup management and disaster recovery | ◐ **Partial** | **26** |
| **Art. 21(2)(d)** — Supply chain security | ◐ **Partial** | **5** |
| **Art. 21(2)(e)** — Security in network and information systems acquisition, development and maintenance | ◐ **Partial** | **13** |
| **Art. 21(2)(f)** — Policies and procedures to assess the effectiveness of risk-management measures | ◐ **Partial** | — |
| **Art. 21(2)(g)** — Cyber hygiene practices and training | ◐ **Partial** | **13** |
| **Art. 21(2)(h)** — Policies and procedures on the use of cryptography and encryption | ✅ **Automated** | **33** |
| **Art. 21(2)(i)** — Human resources security, access control policies and asset management | ◐ **Partial** | **63** |
| **Art. 21(2)(j)** — Authentication and secured communications | ✅ **Automated** | **2** |

### NIS2 Art. 21(2)(a) — Risk analysis and information system security

👤 **Manual**

Risk analysis is an organisational process (registering risks, weighing likelihood and impact, documenting decisions). Terraform/Kubernetes manifests structurally cannot show it — it requires non-IaC evidence such as a risk register and management sign-off.

### NIS2 Art. 21(2)(b) — Incident handling

◐ **Partial**

IaC covers the telemetry slice: audit logging, DB log export, VPC flow logs and monitoring alerts are directly evaluable. Analysis, containment, response playbooks and on-call process are organisational.

Mapped checks (24): `CKV2_AWS_11`, `CKV2_AWS_30`, `CKV2_AWS_62`, `CKV_AWS_101`, `CKV_AWS_118`, `CKV_AWS_126`, `CKV_AWS_129`, `CKV_AWS_18`, `CKV_AWS_317`, `CKV_AWS_324`, `CKV_AWS_325`, `CKV_AWS_338`, `CKV_AWS_353`, `CKV_AWS_37`, `CKV_AWS_50`, `CKV_AWS_84`, `CKV_AWS_92`, `CKV_AZURE_37`, `CKV_AZURE_38`, `CKV_AZURE_66`, `CKV_AZURE_84`, `CKV_GCP_26`, `CKV_GCP_68`, `CKV_GCP_88`.

### NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery

◐ **Partial**

Backup retention, deletion protection and object versioning are directly evaluable. That restores are *tested*, RPO/RTO targets are met and backups sit in a separate failure domain is not.

Mapped checks (26): `CKV2_AWS_58`, `CKV2_AWS_59`, `CKV2_AWS_60`, `CKV2_AWS_61`, `CKV2_AWS_8`, `CKV_AWS_115`, `CKV_AWS_116`, `CKV_AWS_133`, `CKV_AWS_135`, `CKV_AWS_139`, `CKV_AWS_144`, `CKV_AWS_157`, `CKV_AWS_21`, `CKV_AWS_293`, `CKV_AWS_313`, `CKV_AWS_318`, `CKV_AWS_326`, `CKV_AWS_361`, `CKV_AWS_362`, `CKV_GCP_10`, `CKV_K8S_10`, `CKV_K8S_11`, `CKV_K8S_12`, `CKV_K8S_13`, `CKV_K8S_8`, `CKV_K8S_9`.

### NIS2 Art. 21(2)(d) — Supply chain security

◐ **Partial**

Image digests, immutable tags, restricted ingress and registry hardening are evaluable IaC evidence. Vendor security contracts, SBOM review and component qualification are organisational.

Mapped checks (5): `CKV_AZURE_103`, `CKV_AZURE_50`, `CKV_GCP_22`, `CKV_K8S_15`, `CKV_K8S_43`.

### NIS2 Art. 21(2)(e) — Security in network and information systems acquisition, development and maintenance

◐ **Partial**

No hardcoded secrets, up-to-date versions and secure defaults are evaluable. SDLC process, dependency/vulnerability management and disclosure handling are not.

Mapped checks (13): `CKV_AWS_163`, `CKV_AWS_226`, `CKV_AWS_272`, `CKV_AWS_363`, `CKV_AWS_41`, `CKV_AWS_45`, `CKV_AWS_46`, `CKV_AWS_51`, `CKV_K8S_22`, `CKV_K8S_29`, `CKV_K8S_31`, `CKV_K8S_35`, `EUGUARD_NIS2_001`.

### NIS2 Art. 21(2)(f) — Policies and procedures to assess the effectiveness of risk-management measures

◐ **Partial**

No single resource check maps here — the evidence is the tool itself: running tf-eu-guard on every PR and in CI is a repeatable, timestamped effectiveness assessment (mirrors GDPR Art. 32(1)(d)). The documented assessment process around those runs is organisational.

### NIS2 Art. 21(2)(g) — Cyber hygiene practices and training

◐ **Partial**

The configuration slice of cyber hygiene — avoiding public exposure, no host networking, restricted ingress, hardened defaults — is evaluable and mapped in the Azure/GCP/Kubernetes registries. The training-and-behaviour half (staff awareness, password hygiene practice) is organisational and no IaC input can evidence it.

Mapped checks (13): `CKV2_K8S_6`, `CKV_AZURE_11`, `CKV_AZURE_160`, `CKV_AZURE_48`, `CKV_AZURE_53`, `CKV_GCP_20`, `CKV_GCP_23`, `CKV_GCP_25`, `CKV_GCP_27`, `CKV_GCP_38`, `CKV_GCP_6`, `CKV_K8S_19`, `CKV_K8S_28`.

### NIS2 Art. 21(2)(h) — Policies and procedures on the use of cryptography and encryption

✅ **Automated**

Encryption at rest and in transit is fully visible in IaC: KMS configurations, TLS enforcement, encrypted storage and transit settings are directly evaluable. (Key management *policy* around the crypto is organisational, but the requirement's technical measures are automated.)

Mapped checks (33): `CKV2_AWS_2`, `CKV2_AWS_69`, `CKV_AWS_127`, `CKV_AWS_136`, `CKV_AWS_145`, `CKV_AWS_158`, `CKV_AWS_16`, `CKV_AWS_173`, `CKV_AWS_186`, `CKV_AWS_189`, `CKV_AWS_228`, `CKV_AWS_247`, `CKV_AWS_279`, `CKV_AWS_280`, `CKV_AWS_3`, `CKV_AWS_327`, `CKV_AWS_347`, `CKV_AWS_376`, `CKV_AWS_379`, `CKV_AWS_44`, `CKV_AWS_5`, `CKV_AWS_58`, `CKV_AWS_7`, `CKV_AWS_8`, `CKV_AWS_96`, `CKV_AZURE_17`, `CKV_AZURE_3`, `CKV_AZURE_44`, `CKV_AZURE_52`, `CKV_GCP_11`, `CKV_GCP_16`, `CKV_GCP_51`, `CKV_GCP_62`.

### NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management

◐ **Partial**

Strongly covered: SSO/identity federation, MFA, least privilege, public access and asset exposure are directly evaluable. Formal HR security policy and asset-management registers are organisational.

Mapped checks (63): `CKV2_AWS_12`, `CKV2_AWS_40`, `CKV2_AWS_41`, `CKV2_AWS_5`, `CKV2_AWS_52`, `CKV2_AWS_64`, `CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_117`, `CKV_AWS_130`, `CKV_AWS_137`, `CKV_AWS_161`, `CKV_AWS_162`, `CKV_AWS_17`, `CKV_AWS_20`, `CKV_AWS_23`, `CKV_AWS_24`, `CKV_AWS_248`, `CKV_AWS_25`, `CKV_AWS_260`, `CKV_AWS_273`, `CKV_AWS_274`, `CKV_AWS_283`, `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_355`, `CKV_AWS_356`, `CKV_AWS_359`, `CKV_AWS_38`, `CKV_AWS_382`, `CKV_AWS_39`, `CKV_AWS_40`, `CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_70`, `CKV_AWS_79`, `CKV_AWS_9`, `CKV_AZURE_110`, `CKV_AZURE_139`, `CKV_AZURE_35`, `CKV_AZURE_36`, `CKV_AZURE_41`, `CKV_AZURE_45`, `CKV_AZURE_59`, `CKV_AZURE_82`, `CKV_GCP_18`, `CKV_GCP_28`, `CKV_GCP_30`, `CKV_GCP_33`, `CKV_GCP_49`, `CKV_GCP_78`, `CKV_K8S_16`, `CKV_K8S_17`, `CKV_K8S_20`, `CKV_K8S_23`, `CKV_K8S_25`, `CKV_K8S_37`, `CKV_K8S_38`, `CKV_K8S_39`, `CKV_K8S_40`.

### NIS2 Art. 21(2)(j) — Authentication and secured communications

✅ **Automated**

MFA enforcement, authentication configuration and secured communication channels (TLS, disabled legacy protocols, private clusters) are directly evaluable from IaC.

Mapped checks (2): `CKV_AZURE_49`, `CKV_GCP_13`.

## GDPR — Regulation (EU) 2016/679, Art. 32(1) & Art. 44

| Requirement | Coverage | Mapped checks |
|-------------|----------|---------------|
| **Art. 32(1)(a)** — Pseudonymisation and encryption of personal data | ✅ **Automated** | **33** |
| **Art. 32(1)(b)** — Confidentiality, integrity, availability and resilience of processing systems | ◐ **Partial** | **90** |
| **Art. 32(1)(c)** — Ability to restore availability and access to personal data in a timely manner | ◐ **Partial** | **13** |
| **Art. 32(1)(d)** — Regularly testing, assessing and evaluating effectiveness | ◐ **Partial** | **2** |
| **Art. 44** — General principle for transfers of personal data to third countries | ◐ **Partial** | **1** |

### GDPR Art. 32(1)(a) — Pseudonymisation and encryption of personal data

✅ **Automated**

Pseudonymisation is an application-level property, but the encryption the article pairs it with — at rest and in transit — is fully visible in IaC and directly evaluable.

Mapped checks (33): `CKV2_AWS_2`, `CKV2_AWS_69`, `CKV_AWS_127`, `CKV_AWS_136`, `CKV_AWS_145`, `CKV_AWS_158`, `CKV_AWS_16`, `CKV_AWS_173`, `CKV_AWS_186`, `CKV_AWS_189`, `CKV_AWS_228`, `CKV_AWS_247`, `CKV_AWS_279`, `CKV_AWS_280`, `CKV_AWS_3`, `CKV_AWS_327`, `CKV_AWS_347`, `CKV_AWS_376`, `CKV_AWS_379`, `CKV_AWS_44`, `CKV_AWS_5`, `CKV_AWS_58`, `CKV_AWS_7`, `CKV_AWS_8`, `CKV_AWS_96`, `CKV_AZURE_17`, `CKV_AZURE_3`, `CKV_AZURE_44`, `CKV_AZURE_52`, `CKV_GCP_11`, `CKV_GCP_16`, `CKV_GCP_51`, `CKV_GCP_62`.

### GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems

◐ **Partial**

Broadly covered: access control, network isolation, logging, encryption and resilience settings are evaluable. Overall CIA also depends on runtime posture no static manifest shows.

Mapped checks (90): `CKV2_AWS_30`, `CKV2_AWS_40`, `CKV2_AWS_52`, `CKV2_AWS_58`, `CKV2_AWS_6`, `CKV2_AWS_64`, `CKV2_K8S_6`, `CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_115`, `CKV_AWS_130`, `CKV_AWS_135`, `CKV_AWS_137`, `CKV_AWS_139`, `CKV_AWS_161`, `CKV_AWS_163`, `CKV_AWS_17`, `CKV_AWS_20`, `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AWS_283`, `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_317`, `CKV_AWS_318`, `CKV_AWS_324`, `CKV_AWS_325`, `CKV_AWS_338`, `CKV_AWS_355`, `CKV_AWS_356`, `CKV_AWS_363`, `CKV_AWS_38`, `CKV_AWS_41`, `CKV_AWS_45`, `CKV_AWS_46`, `CKV_AWS_51`, `CKV_AWS_53`, `CKV_AWS_54`, `CKV_AWS_55`, `CKV_AWS_56`, `CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_70`, `CKV_AWS_79`, `CKV_AZURE_11`, `CKV_AZURE_110`, `CKV_AZURE_139`, `CKV_AZURE_160`, `CKV_AZURE_35`, `CKV_AZURE_36`, `CKV_AZURE_37`, `CKV_AZURE_38`, `CKV_AZURE_41`, `CKV_AZURE_45`, `CKV_AZURE_48`, `CKV_AZURE_49`, `CKV_AZURE_50`, `CKV_AZURE_53`, `CKV_AZURE_59`, `CKV_AZURE_66`, `CKV_AZURE_82`, `CKV_GCP_13`, `CKV_GCP_18`, `CKV_GCP_20`, `CKV_GCP_22`, `CKV_GCP_23`, `CKV_GCP_25`, `CKV_GCP_26`, `CKV_GCP_27`, `CKV_GCP_28`, `CKV_GCP_30`, `CKV_GCP_33`, `CKV_GCP_38`, `CKV_GCP_49`, `CKV_GCP_6`, `CKV_GCP_68`, `CKV_GCP_78`, `CKV_GCP_88`, `CKV_K8S_16`, `CKV_K8S_17`, `CKV_K8S_19`, `CKV_K8S_20`, `CKV_K8S_23`, `CKV_K8S_31`, `CKV_K8S_35`, `CKV_K8S_39`, `EUGUARD_NIS2_001`.

### GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner

◐ **Partial**

Backup, versioning, multi-AZ and retention — the ability to restore — are evaluable. Whether restores actually happen in a timely manner (tested RTO) is operational evidence, not IaC.

Mapped checks (13): `CKV2_AWS_8`, `CKV_AWS_133`, `CKV_AWS_144`, `CKV_AWS_157`, `CKV_AWS_21`, `CKV_AWS_293`, `CKV_AWS_326`, `CKV_AWS_361`, `CKV_GCP_10`, `CKV_K8S_10`, `CKV_K8S_12`, `CKV_K8S_8`, `CKV_K8S_9`.

### GDPR Art. 32(1)(d) — Regularly testing, assessing and evaluating effectiveness

◐ **Partial**

Same shape as NIS2 21(2)(f): continuous scanning in CI is the technical evidence of regular testing; the testing *process* (pen tests, review cadence) is organisational.

Mapped checks (2): `CKV_AZURE_103`, `CKV_AZURE_84`.

### GDPR Art. 44 — General principle for transfers of personal data to third countries

◐ **Partial**

The custom EUGUARD_GDPR_001 check flags non-EU provider regions as a transfer requiring Chapter V justification. The adequacy/SCC analysis itself is legal, not technical — a non-EU region is a strong signal, not a violation.

Mapped checks (1): `EUGUARD_GDPR_001`.

---

Related: [`docs/nis2-mapping.md`](nis2-mapping.md) and [`docs/gdpr-mapping.md`](gdpr-mapping.md) give the per-check evidence and limitations; [`docs/check-mapping-table.md`](check-mapping-table.md) is the full check-level matrix. Guiding principle: this project is measured by mapping *quality*, tracked honestly here — automated vs. partial vs. manual vs. not covered — not by a single 'N checks mapped' headline number.
