"""Requirement-level regulatory coverage model.

Classifies each requirement of NIS2 Art. 21(2)(a)–(j) and GDPR
Art. 32(1)(a)–(d) (plus GDPR Art. 44, which the custom residency check
maps) into one of four categories, so a user can tell "this requirement
has automated checks" from "this requirement has never been looked at":

- **Automated** — the tool can directly evaluate this from IaC input today
- **Partial** — the technical config provides evidence for only part of
  the requirement
- **Manual** — needs non-IaC evidence (policy, governance, staff
  training, incident-response process) that Terraform/Kubernetes
  manifests structurally can never show
- **Not covered** — no current mapping

The inventory lives in :data:`REQUIREMENTS` (authored once, deliberately
not invented beyond what the registries already map). The *per-requirement
check counts* are computed from the registries at run time, never
hand-typed — see ``tools/generate_coverage_doc.py``, which renders
``docs/regulatory-coverage.md`` from this module.
"""

from dataclasses import dataclass
from enum import StrEnum

from tf_eu_guard.models import ComplianceMapping, Framework

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
    "g": "Cyber hygiene practices and training",
    "h": "Policies and procedures on the use of cryptography and encryption",
    "i": "Human resources security, access control policies and asset management",
    "j": "Authentication and secured communications",
}

#: GDPR requirement key -> canonical short title. Art. 32(1)(a)–(d) plus
#: Art. 44 (transfers — covered by the custom EUGUARD_GDPR_001 check).
GDPR_TITLES: dict[str, str] = {
    "32(1)(a)": "Pseudonymisation and encryption of personal data",
    "32(1)(b)": "Confidentiality, integrity, availability and resilience of processing systems",
    "32(1)(c)": "Ability to restore availability and access to personal data in a timely manner",
    "32(1)(d)": "Regularly testing, assessing and evaluating effectiveness",
    "44": "General principle for transfers of personal data to third countries",
}


class CoverageCategory(StrEnum):
    """How much of a requirement this tool can evaluate from IaC."""

    AUTOMATED = "automated"
    PARTIAL = "partial"
    MANUAL = "manual"
    NOT_COVERED = "not covered"


@dataclass(frozen=True)
class RequirementCoverage:
    """One requirement in the inventory and how well it is covered."""

    framework: Framework
    article: str  # e.g. "21(2)(b)" or "32(1)(a)"
    letter: str  # NIS2 letter ("b") or GDPR key ("32(1)(a)"); == article for NIS2
    title: str
    category: CoverageCategory
    #: Free-text justification; for Manual/Not covered this IS the
    #: documentation of why, for Partial it names what IaC covers vs. not.
    rationale: str
    #: Registry check IDs mapped to this requirement — populated at load
    #: time by :func:`compute_coverage`, never hand-typed.
    checks: tuple[str, ...] = ()

    @property
    def check_count(self) -> int:
        return len(self.checks)

    @property
    def article_label(self) -> str:
        """Full article citation, e.g. 'NIS2 Art. 21(2)(b)'."""
        return f"Art. {self.article}"


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
            "Kubernetes manifests structurally cannot show it — it requires "
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
        category=CoverageCategory.PARTIAL,
        rationale=(
            "No single resource check maps here — the evidence is the tool "
            "itself: running tf-eu-guard on every PR and in CI is a repeatable, "
            "timestamped effectiveness assessment (mirrors GDPR Art. 32(1)(d)). "
            "The documented assessment process around those runs is organisational."
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
        category=CoverageCategory.AUTOMATED,
        rationale=(
            "Encryption at rest and in transit is fully visible in IaC: KMS "
            "configurations, TLS enforcement, encrypted storage and transit "
            "settings are directly evaluable. (Key management *policy* around "
            "the crypto is organisational, but the requirement's technical "
            "measures are automated.)"
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
        category=CoverageCategory.AUTOMATED,
        rationale=(
            "MFA enforcement, authentication configuration and secured "
            "communication channels (TLS, disabled legacy protocols, private "
            "clusters) are directly evaluable from IaC."
        ),
    ),
    # --- GDPR ---
    dict(
        framework=Framework.GDPR,
        letter="32(1)(a)",
        category=CoverageCategory.AUTOMATED,
        rationale=(
            "Pseudonymisation is an application-level property, but the "
            "encryption the article pairs it with — at rest and in transit — "
            "is fully visible in IaC and directly evaluable."
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
            "Backup, versioning, multi-AZ and retention — the ability to "
            "restore — are evaluable. Whether restores actually happen in a "
            "timely manner (tested RTO) is operational evidence, not IaC."
        ),
    ),
    dict(
        framework=Framework.GDPR,
        letter="32(1)(d)",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "Same shape as NIS2 21(2)(f): continuous scanning in CI is the "
            "technical evidence of regular testing; the testing *process* "
            "(pen tests, review cadence) is organisational."
        ),
    ),
    dict(
        # Custom check EUGUARD_GDPR_001: provider region -> transfer signal.
        # Deliberately the honest mid category: the config is evaluable, the
        # lawful-transfer analysis is not (docs/gdpr-mapping.md standard).
        framework=Framework.GDPR,
        letter="44",
        category=CoverageCategory.PARTIAL,
        rationale=(
            "The custom EUGUARD_GDPR_001 check flags non-EU provider regions "
            "as a transfer requiring Chapter V justification. The adequacy/SCC "
            "analysis itself is legal, not technical — a non-EU region is a "
            "strong signal, not a violation."
        ),
    ),
)


def _article_key(framework: Framework, article: str) -> tuple[str, str]:
    """Normalize a registry article string to an inventory key.

    NIS2 "Art. 21(2)(b)" -> ("NIS2", "b"); GDPR "Art. 32(1)(a)" ->
    ("GDPR", "32(1)(a)"); GDPR "Art. 44" -> ("GDPR", "44"). Unknown
    shapes return a key that simply matches nothing in the inventory.
    """
    text = article.removeprefix("Art. ").strip()
    if framework == Framework.NIS2:
        if text.startswith("21(2)(") and text.endswith(")"):
            return (framework.value, text.removeprefix("21(2)(")[0])
        return (framework.value, "")
    return (framework.value, text)


def compute_coverage(
    registry: dict[str, ComplianceMapping],
) -> list[RequirementCoverage]:
    """
    Build the requirement inventory with live per-requirement check IDs.

    The categories and rationales come from :data:`REQUIREMENTS`; the check
    IDs are computed from ``registry`` — every registry mapping citing the
    requirement is attributed to it, so counts can never drift from the
    registries the way the README's hand-typed ones once did.
    """
    by_key: dict[tuple[str, str], list[str]] = {}
    for check_id, mapping in registry.items():
        for article in mapping.articles:
            key = _article_key(article.framework, article.article)
            by_key.setdefault(key, []).append(check_id)

    coverage: list[RequirementCoverage] = []
    for entry in REQUIREMENTS:
        letter = entry["letter"]
        if entry["framework"] == Framework.NIS2:
            article = f"21(2)({letter})"
            title = NIS2_TITLES[letter]
        else:
            article = letter
            title = GDPR_TITLES[letter]
        checks = tuple(
            sorted(
                set(
                    by_key.get(
                        (entry["framework"].value, letter), []
                    )
                )
            )
        )
        coverage.append(
            RequirementCoverage(
                framework=entry["framework"],
                article=article,
                letter=letter,
                title=title,
                category=entry["category"],
                rationale=entry["rationale"],
                checks=checks,
            )
        )
    return coverage


def coverage_summary(coverage: list[RequirementCoverage]) -> dict[str, int]:
    """Count requirements per category, e.g. for report headlines."""
    summary = {category.value: 0 for category in CoverageCategory}
    for requirement in coverage:
        summary[requirement.category.value] += 1
    return summary
