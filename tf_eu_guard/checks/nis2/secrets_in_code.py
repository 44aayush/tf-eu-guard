"""
Custom Checkov check: hardcoded secrets in Terraform resource configuration.

Literal credentials committed to IaC (database passwords, auth tokens, private
keys) are readable by anyone with repository or state access, cannot be rotated
centrally, and routinely leak through CI logs. Storing secrets in code is an
insecure development/maintenance practice under NIS2 Art. 21(2)(e); where the
secret guards personal data it is also a confidentiality risk under GDPR
Art. 32(1)(b).

Checkov renders variable defaults before checks run, so a ``var.db_password``
whose default is a literal is caught here too — which is the intent. References
to other resources/data sources (e.g. ``data.aws_secretsmanager_secret_version``,
rendered as ``"${...}"``) and unset values are treated as compliant.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from tf_eu_guard.checks.nis2.secret_names import (
    is_literal_env_value,
    is_sensitive_env_name,
)

# Resource types that carry a plaintext-secret argument, mapped to the
# argument name(s) that must never hold a literal value.
_SECRET_FIELDS_BY_RESOURCE = {
    "aws_db_instance": ("password",),
    "aws_rds_cluster": ("master_password",),
    "aws_redshift_cluster": ("master_password",),
    "aws_docdb_cluster": ("master_password",),
    "aws_elasticache_replication_group": ("auth_token",),
}
_SECRET_REFERENCE_TYPES = {"SECRETS_MANAGER", "PARAMETER_STORE"}


class HardcodedSecrets(BaseResourceCheck):
    """Flag resources whose sensitive arguments contain a literal secret."""

    def __init__(self):
        name = "Ensure secrets are not hardcoded in Terraform (use variables/Secrets Manager)"
        check_id = "EUGUARD_NIS2_001"
        supported_resources = tuple((*_SECRET_FIELDS_BY_RESOURCE, "aws_codebuild_project"))
        categories = [CheckCategories.SECRETS]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        """FAILED if any sensitive argument holds a literal string; else PASSED.

        The resource type is read from ``self.entity_type`` (set by Checkov's
        ``scan_entity_conf`` before this runs) to pick the right argument names.
        """
        if self.entity_type == "aws_codebuild_project":
            if _scan_codebuild_env(conf):
                self.evaluated_keys = ["environment.environment_variable"]
                return CheckResult.FAILED
            return CheckResult.PASSED

        for field in _SECRET_FIELDS_BY_RESOURCE.get(self.entity_type, ()):
            value = _first_scalar(conf.get(field))
            if _is_hardcoded_secret(value):
                self.evaluated_keys = [field]
                return CheckResult.FAILED
        return CheckResult.PASSED


def _scan_codebuild_env(conf: dict) -> bool:
    """Return whether CodeBuild contains a literal sensitive PLAINTEXT value.

    Checkov wraps nested Terraform blocks in one-element lists, so the
    traversal accepts either the raw mapping shape or those wrappers.  AWS
    secret/parameter-store references are safe references, not secret values.
    """
    environment = _first_scalar(conf.get("environment"))
    if not isinstance(environment, dict):
        return False
    variables = environment.get("environment_variable", [])
    for variable in _mapping_values(variables):
        variable_type = str(_first_scalar(variable.get("type")) or "PLAINTEXT").upper()
        if variable_type in _SECRET_REFERENCE_TYPES:
            continue
        name = _first_scalar(variable.get("name"))
        value = _first_scalar(variable.get("value"))
        if is_sensitive_env_name(name) and is_literal_env_value(value):
            return True
    return False


def _mapping_values(value):
    """Yield mappings from Checkov's nested list/mapping representation."""
    if isinstance(value, dict):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _mapping_values(item)


def _is_hardcoded_secret(value) -> bool:
    """True when ``value`` is a non-empty literal string (not an interpolation)."""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    # A "${...}" reference to a var/resource/data source is not a hardcoded literal.
    if stripped.startswith("${") and stripped.endswith("}"):
        return False
    return True


def _first_scalar(value):
    """Unwrap Checkov's single-element list wrapping around attribute values."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


check = HardcodedSecrets()
