"""Regulatory requirement data: NIS2/GDPR titles, categories, and inventory.

Pure data, authored once. The titles canonicalize the registry's own article
wordings; the inventory records a human judgement per requirement — how much
of it IaC can structurally show — which the coverage *model*
(:mod:`tf_eu_guard.mapping.coverage`) joins with live registry check IDs at
run time. Keeping the data here separates "what we claim about each
requirement" from the code that computes and renders it. ``CoverageCategory``
lives here (not in the model) because the inventory entries reference it —
importing it from ``coverage`` would create a cycle.
"""

from enum import StrEnum

from tf_eu_guard.models import Framework


class CoverageCategory(StrEnum):
    """How much of a requirement this tool can evaluate from IaC."""

    AUTOMATED = "automated"
    PARTIAL = "partial"
    #: No resource check maps here; the tool's own repeatable CI runs are
    #: the evidence. Distinct from PARTIAL, which implies mapped checks.
    PROCESS_EVIDENCE = "process evidence"
    MANUAL = "manual"
    NOT_COVERED = "not covered"


#: NIS2 Art. 21(2) letter -> canonical short title. Letters follow
#: Directive (EU) 2022/2555 Art. 21(2)(a)–(j); titles are the registry's
#: own article titles, reconciled to one wording per letter.
NIS2_TITLES: dict[str, str] = {
    "a": "Risk analysis and information system security",
    "b": "Incident handling",
    "c": "Business continuity, backup management and disaster recovery",
    "d": "Supply chain security",
    "e": "Security in network and information systems acquisition, development and maintenance",
    "f": "Policies and procedures to assess the effectiveness of risk-management measures",
    "g": "Basic cyber hygiene practices and cybersecurity training",
    "h": "Policies and procedures on the use of cryptography and encryption",
    "i": "Human resources security, access control policies and asset management",
    "j": "Authentication and secured communications",
}

#: GDPR requirement key -> canonical short title. Art. 32(1)(a)–(d) plus
#: the breach-notification/definition references used by registry risk text and
#: Art. 44 (transfers — covered by the custom EUGUARD_GDPR_002 check).
GDPR_TITLES: dict[str, str] = {
    "4(12)": "Personal data breach",
    "32(1)(a)": "Pseudonymisation and encryption of personal data",
    "32(1)(b)": "Confidentiality, integrity, availability and resilience of processing systems",
    "32(1)(c)": "Ability to restore availability and access to personal data in a timely manner",
    "32(1)(d)": "Regularly testing, assessing and evaluating effectiveness",
    "33": "Notification of a personal data breach to the supervisory authority",
    "44": "General principle for transfers of personal data to third countries",
}

#: Canonical article labels used by every registry entry and report. Keeping
#: these in one table prevents the auditor report from inheriting whichever
#: registry happened to be loaded first.
ARTICLE_TITLES: dict[tuple[Framework, str], str] = {
    **{(Framework.NIS2, f"Art. 21(2)({letter})"): title for letter, title in NIS2_TITLES.items()},
    **{(Framework.GDPR, f"Art. {article}"): title for article, title in GDPR_TITLES.items()},
    (Framework.POLICY, "Policy RESIDENCY-001"): "Region residency policy",
}


def canonical_article_title(framework: Framework, article: str) -> str | None:
    """Return the authoritative title for an article reference."""
    return ARTICLE_TITLES.get((framework, article))


# ---------------------------------------------------------------------------
# The inventory. Authored once: classifications and rationales are human
# judgements (they encode what IaC can structurally show), but every
# *check* attributed to a requirement below is computed from the live
# registries — if a mapping is added or removed, the counts follow.
# Classifications were reconciled with docs/nis2-mapping.md and
# docs/gdpr-mapping.md: e.g. (a)/(g) are documented there as
# "organisational, intentionally out of scope", which here is the honest
# label "manual" rather than silence.
# ---------------------------------------------------------------------------

REQUIREMENTS: tuple[dict, ...] = (
    # --- NIS2 Art. 21(2) ---
    dict(
        framework=Framework.NIS2,
        letter="a",
        category=CoverageCategory.MANUAL,
        rationale=(
            "Risk analysis is an organisational process (registering risks, "
            "weighing likelihood and impact, documenting decisions). Terraform/"
            "Kubernetes manifests structurally cannot show it. It requires "
            "non-IaC evidence such as a risk register and management sign-off."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="b",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "IaC covers the telemetry slice: audit logging, DB log export, VPC "
            "flow logs and monitoring alerts are directly evaluable. Analysis, "
            "containment, response playbooks and on-call process are organisational."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="c",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Backup retention, deletion protection and object versioning are "
            "directly evaluable. That restores are *tested*, RPO/RTO targets "
            "are met and backups sit in a separate failure domain is not."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="d",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Image digests, immutable tags, restricted ingress and registry "
            "hardening are evaluable IaC evidence. Vendor security contracts, "
            "SBOM review and component qualification are organisational."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="e",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "No hardcoded secrets, up-to-date versions and secure defaults are "
            "evaluable. SDLC process, dependency/vulnerability management and "
            "disclosure handling are not."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="f",
        category=CoverageCategory.PROCESS_EVIDENCE,
        rationale=(
            "No resource check maps here and none can: the evidence is the "
            "tool's own use. Running tf-eu-guard on every PR and in CI yields "
            "repeatable, timestamped scan output that an assessment process "
            "can cite. That is process evidence, not an evaluated control; the "
            "documented assessment process around those runs is organisational "
            "(mirrors GDPR Art. 32(1)(d))."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="g",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "The configuration slice of cyber hygiene — avoiding public "
            "exposure, no host networking, restricted ingress, hardened "
            "defaults — is evaluable and mapped in the Azure/GCP/Kubernetes "
            "registries. The training-and-behaviour half (staff awareness, "
            "password hygiene practice) is organisational and no IaC input "
            "can evidence it."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="h",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "The article concerns *policies and procedures* on cryptography. "
            "IaC shows the technical slice: encryption at rest and in transit, "
            "KMS configuration and TLS enforcement are directly evaluable. "
            "Whether a cryptography policy exists, key lifecycle and rotation "
            "procedures, algorithm selection rationale and key custody are "
            "organisational and not visible in IaC."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="i",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Strongly covered: SSO/identity federation, MFA, least privilege, "
            "public access and asset exposure are directly evaluable. Formal "
            "HR security policy and asset-management registers are organisational."
        ),
    ),
    dict(
        framework=Framework.NIS2,
        letter="j",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "The article covers multi-factor authentication and secured "
            "voice, video, text and emergency communications. The mapped "
            "checks evaluate only a narrow slice: client certificates, basic "
            "authentication and TLS or legacy-protocol settings on "
            "infrastructure. MFA enrolment and enforcement for people, and "
            "the security of voice, video, messaging and emergency "
            "communication systems, are outside what IaC shows."
        ),
    ),
    # --- GDPR ---
    dict(
        framework=Framework.GDPR,
        letter="32(1)(a)",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Only the encryption half is evaluable: encryption at rest and in "
            "transit is visible in IaC. Pseudonymisation is an "
            "application-level property that cannot be evaluated from "
            "infrastructure configuration, so the requirement as a whole is "
            "only partly covered."
        ),
    ),
    dict(
        framework=Framework.GDPR,
        letter="32(1)(b)",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Broadly covered: access control, network isolation, logging, "
            "encryption and resilience settings are evaluable. Overall CIA "
            "also depends on runtime posture no static manifest shows."
        ),
    ),
    dict(
        framework=Framework.GDPR,
        letter="32(1)(c)",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Backup, versioning, multi-AZ and retention (the ability to "
            "restore) are evaluable. Whether restores actually happen in a "
            "timely manner (tested RTO) is operational evidence, not IaC."
        ),
    ),
    dict(
        framework=Framework.GDPR,
        letter="32(1)(d)",
        category=CoverageCategory.PROCESS_EVIDENCE,
        rationale=(
            "Same shape as NIS2 21(2)(f): the evidence is the tool's own use. "
            "Continuous scanning in CI produces repeatable evidence that "
            "testing happens, which is process evidence rather than an "
            "evaluated control; the few mapped checks (Azure Data Factory and Defender "
            "settings) do not evidence the requirement itself. The testing "
            "*process* (pen tests, review cadence) is organisational."
        ),
    ),
    dict(
        # Custom check EUGUARD_GDPR_002: known third-country provider region ->
        # transfer review signal. EUGUARD_POLICY_001/002 are separate project-policy
        # control and is intentionally not part of this regulatory inventory.
        # Deliberately the honest mid category: the config is evaluable, the
        # lawful-transfer analysis is not (docs/gdpr-mapping.md standard).
        framework=Framework.GDPR,
        letter="44",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "The custom EUGUARD_GDPR_002 and EUGUARD_GDPR_003 checks flag known AWS "
            "provider and resource-level regions and Azure resource locations outside the EU/EEA "
            "for Chapter V review (EUGUARD_GDPR_004 covers Azure). The adequacy/SCC analysis "
            "itself is legal, not technical. A third-country signal is a prompt "
            "for review, not a violation or definitive legal conclusion."
        ),
    ),
)
