"""Collect the AWS regions that a Terraform resource configuration names.

Shared by ``EUGUARD_POLICY_002`` and ``EUGUARD_GDPR_003``. Checkov hands
resource attributes over as nested lists (``{"replica": [{"region_name":
["us-east-1"]}]}``); this module walks those shapes and returns each region
with the attribute that carries it.

Covered: the top-level ``region`` argument (AWS provider >= 6.0 accepts it on
most resources) and the replica/replication settings that place data in
another region regardless of the provider. ``aws_s3_bucket_replication_
configuration`` destinations are bucket ARNs whose region cannot be derived
statically, so they are not collected.
"""

import re
from typing import Any, NamedTuple

from tf_eu_guard.checks.values import unwrap_checkov_scalar

# (resource type, attribute path) pairs whose value is a region code.
_NESTED_REGION_ATTRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aws_dynamodb_table", ("replica", "region_name")),
    ("aws_secretsmanager_secret", ("replica", "region")),
    (
        "aws_ecr_replication_configuration",
        ("replication_configuration", "rule", "destination", "region"),
    ),
)
# (resource type, attribute path) pairs whose value is a Backup vault ARN.
_ARN_ATTRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aws_backup_plan", ("rule", "copy_action", "destination_vault_arn")),
)
_BACKUP_ARN_RE = re.compile(r"^arn:[a-z-]+:backup:([a-z0-9-]+):")


class RegionRef(NamedTuple):
    """One region named by a resource, and the attribute that names it."""

    region: str
    key: str


def _walk(node: Any, path: tuple[str, ...], prefix: str) -> list[tuple[Any, str]]:
    """Return ``(raw value, evaluated key)`` for every match of *path*."""
    if isinstance(node, list):
        out: list[tuple[Any, str]] = []
        for index, item in enumerate(node):
            if isinstance(item, dict):
                out.extend(_walk(item, path, f"{prefix}/[{index}]" if len(node) > 1 else prefix))
        return out
    if not isinstance(node, dict) or path[0] not in node:
        return []
    key = f"{prefix}/{path[0]}" if prefix else path[0]
    value = node[path[0]]
    if len(path) == 1:
        return [(value, key)]
    return _walk(value, path[1:], key)


def _as_region(raw: Any) -> str | None:
    value = unwrap_checkov_scalar(raw)
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def collect_regions(resource_type: str, conf: dict[str, Any]) -> list[RegionRef]:
    """Return every statically visible region named by this resource."""
    refs: list[RegionRef] = []

    for raw, key in _walk(conf, ("region",), ""):
        region = _as_region(raw)
        if region is not None:
            refs.append(RegionRef(region, key))

    for rtype, path in _NESTED_REGION_ATTRS:
        if rtype != resource_type:
            continue
        for raw, key in _walk(conf, path, ""):
            region = _as_region(raw)
            if region is not None:
                refs.append(RegionRef(region, key))

    for rtype, path in _ARN_ATTRS:
        if rtype != resource_type:
            continue
        for raw, key in _walk(conf, path, ""):
            arn = _as_region(raw)
            match = _BACKUP_ARN_RE.match(arn) if arn else None
            # An unresolved ARN (variable or interpolation) names no region.
            if match:
                refs.append(RegionRef(match.group(1), key))
    return refs
