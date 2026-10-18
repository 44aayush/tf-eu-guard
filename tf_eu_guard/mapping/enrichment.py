"""Join Checkov findings with the loaded compliance registry."""

from typing import Any

from tf_eu_guard.models import ComplianceMapping, EnrichedFinding


def split_findings(
    checkov_findings: list[dict[str, Any]],
    registry: dict[str, ComplianceMapping],
) -> tuple[list[EnrichedFinding], list[dict[str, Any]]]:
    """Partition Checkov findings into enriched and unmapped collections."""
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
