"""Mapping registry loader — joins Checkov findings with EU compliance articles.

Loads every ``registry-*.yaml`` file in the mapping directory and merges them
into one registry (check_id -> ComplianceMapping), with schema validation.
"""

from pathlib import Path
from typing import Any

import yaml

from tf_eu_guard.models import (
    ArticleReference,
    ComplianceMapping,
    EnrichedFinding,
    Framework,
    Severity,
)

VALID_SEVERITIES = {s.value for s in Severity}
VALID_FRAMEWORKS = {f.value for f in Framework}

REQUIRED_FIELDS = ("check_name", "articles", "risk", "remediation", "severity")


class RegistryValidationError(ValueError):
    """Raised when a registry file violates the mapping schema."""


def _validate_entry(check_id: str, data: dict[str, Any], source: Path) -> None:
    """Validate one registry entry against the mapping schema."""
    where = f"{source.name}:{check_id}"
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] in (None, "", []):
            raise RegistryValidationError(f"{where}: missing required field '{field}'")

    if data["severity"] not in VALID_SEVERITIES:
        raise RegistryValidationError(
            f"{where}: severity '{data['severity']}' not in {sorted(VALID_SEVERITIES)}"
        )

    articles = data["articles"]
    if not isinstance(articles, list):
        raise RegistryValidationError(f"{where}: 'articles' must be a list")

    for article in articles:
        for field in ("framework", "article", "title"):
            if field not in article or not article[field]:
                raise RegistryValidationError(
                    f"{where}: article missing required field '{field}'"
                )
        if article["framework"] not in VALID_FRAMEWORKS:
            raise RegistryValidationError(
                f"{where}: framework '{article['framework']}' not in "
                f"{sorted(VALID_FRAMEWORKS)}"
            )


def load_registry_file(registry_path: Path) -> dict[str, ComplianceMapping]:
    """Load and validate a single registry YAML file."""
    with open(registry_path) as f:
        raw_registry = yaml.safe_load(f) or {}

    mappings = {}
    for check_id, data in raw_registry.items():
        _validate_entry(check_id, data, registry_path)
        articles = [
            ArticleReference(
                framework=Framework(article["framework"]),
                article=article["article"],
                title=article["title"],
            )
            for article in data["articles"]
        ]

        mappings[check_id] = ComplianceMapping(
            check_id=check_id,
            check_name=data.get("check_name", ""),
            articles=articles,
            risk_explanation=data["risk"],
            remediation=data["remediation"],
            severity=Severity(data["severity"]),
        )

    return mappings


def load_registry(registry_path: Path) -> dict[str, ComplianceMapping]:
    """
    Load a compliance mapping registry from YAML.

    Accepts either a single registry file (``registry-*.yaml``) or — when given
    the mapping directory — merges every ``registry-*.yaml`` file found there.
    """
    if registry_path.is_dir():
        merged: dict[str, ComplianceMapping] = {}
        for path in sorted(registry_path.glob("registry-*.yaml")):
            for check_id, mapping in load_registry_file(path).items():
                if check_id in merged:
                    raise RegistryValidationError(
                        f"duplicate check_id '{check_id}' in {path.name}"
                    )
                merged[check_id] = mapping
        return merged

    return load_registry_file(registry_path)


def validate_all(mapping_dir: Path | None = None) -> dict[str, int]:
    """Validate every registry file against the schema.

    Returns a dict of {filename: entry_count}. Raises RegistryValidationError
    on the first schema violation. Used by CI and tests.
    """
    mapping_dir = mapping_dir or Path(__file__).parent
    counts = {}
    for path in sorted(mapping_dir.glob("registry-*.yaml")):
        mappings = load_registry_file(path)
        if not mappings:
            raise RegistryValidationError(f"{path.name}: no entries found")
        counts[path.name] = len(mappings)
    if not counts:
        raise RegistryValidationError(f"no registry-*.yaml files found in {mapping_dir}")
    return counts


def split_findings(
    checkov_findings: list[dict[str, Any]],
    registry: dict[str, ComplianceMapping],
) -> tuple[list[EnrichedFinding], list[dict[str, Any]]]:
    """
    Partition Checkov findings into (enriched, unmapped).

    Args:
        checkov_findings: List of failed checks from Checkov
        registry: Loaded compliance mapping registry

    Returns:
        A tuple of:

        - the findings whose check ID has a registry entry, enriched with EU
          compliance context
        - the raw Checkov finding dicts with **no** registry entry, preserved
          so callers can surface them instead of silently dropping them
          (e.g. "52 mapped findings, 9 unmapped").
    """
    enriched: list[EnrichedFinding] = []
    unmapped: list[dict[str, Any]] = []

    for check in checkov_findings:
        check_id = check["check_id"]
        mapping = registry.get(check_id)

        if not mapping:
            # No EU compliance mapping — keep the raw finding so reports can
            # show it as present-but-unmapped rather than absent.
            unmapped.append(check)
            continue

        enriched.append(
            EnrichedFinding(
                check_id=check_id,
                check_name=check["check_name"],
                resource=check["resource"],
                file_path=check["file_path"],
                file_line_range=check["file_line_range"],
                guideline=check.get("guideline"),
                articles=mapping.articles,
                risk_explanation=mapping.risk_explanation,
                remediation=mapping.remediation,
                severity=mapping.severity,
            )
        )

    return enriched, unmapped


def enrich_findings(
    checkov_findings: list[dict[str, Any]],
    registry: dict[str, ComplianceMapping],
) -> list[EnrichedFinding]:
    """
    Enrich Checkov findings with EU compliance context from registry.

    Only findings with a registry mapping are returned. Findings whose check
    ID has no mapping are dropped here — use :func:`split_findings` when the
    unmapped findings also need to be surfaced (the CLI does).

    Args:
        checkov_findings: List of failed checks from Checkov
        registry: Loaded compliance mapping registry

    Returns:
        List of enriched findings with EU article mappings
    """
    return split_findings(checkov_findings, registry)[0]
