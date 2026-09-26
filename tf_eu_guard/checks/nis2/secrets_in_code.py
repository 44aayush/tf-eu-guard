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

``aws_codebuild_project`` is the exception in shape: its sensitive argument is
the nested ``environment_variable`` block, not a top-level attribute. Terraform
has no type system to mark an env var sensitive, so the variable *name*
(PASSWORD/TOKEN/SECRET/KEY/...) is the signal — the same convention the
Kubernetes variant of this check uses.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

# Env-var name fragments that mark the value as sensitive — the same convention
# the Kubernetes variant of this check uses (checks/k8s/secrets_in_code.py).
_SENSITIVE_NAME_FRAGMENTS = (
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_key", "private_key", "credential",
)

# Resource types that carry a plaintext-secret argument, mapped to the
# argument name(s) that must never hold a literal value. For
# aws_codebuild_project the sensitive argument is the *nested*
# environment_variable block, which is handled separately in
# scan_resource_conf (its name/value pairs arrive as a list of dicts).
_SECRET_FIELDS_BY_RESOURCE = {
    "aws_db_instance": ("password",),
    "aws_rds_cluster": ("master_password",),
    "aws_redshift_cluster": ("master_password",),
    "aws_docdb_cluster": ("master_password",),
    "aws_elasticache_replication_group": ("auth_token",),
    "aws_codebuild_project": (),
}


class HardcodedSecrets(BaseResourceCheck):
    """Flag resources whose sensitive arguments contain a literal secret."""

    def __init__(self):
        name = "Ensure secrets are not hardcoded in Terraform (use variables/Secrets Manager)"
        check_id = "EUGUARD_NIS2_001"
        supported_resources = tuple(_SECRET_FIELDS_BY_RESOURCE)
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
        for field in _SECRET_FIELDS_BY_RESOURCE.get(self.entity_type, ()):
            value = _first_scalar(conf.get(field))
            if _is_hardcoded_secret(value):
                self.evaluated_keys = [field]
                return CheckResult.FAILED
        if self.entity_type == "aws_codebuild_project":
            # environment_variable is a nested block, not a top-level attribute,
            # so it needs its own scan path (see _scan_codebuild_env).
            self.evaluated_keys = _scan_codebuild_env(conf)
            if self.evaluated_keys:
                return CheckResult.FAILED
        return CheckResult.PASSED


def _scan_codebuild_env(conf) -> list[str]:
    """Scan the nested ``environment_variable`` blocks for a literal secret.

    CodeBuild has no type system to mark an env var sensitive, so the variable
    *name* (PASSWORD/TOKEN/SECRET/KEY/...) is the signal — the same convention
    the Kubernetes variant of this check uses. Returns the evaluated key of the
    offending entry, or an empty list when nothing fails.
    """
    for idx, entry in _env_var_entries(conf.get("environment")):
        name = str(_first_scalar(entry.get("name", ""))).lower()
        if _is_hardcoded_secret(_first_scalar(entry.get("value"))) and (
            _is_sensitive_env_name(name)
        ):
            return [f"environment/[0]/environment_variable/[{idx}]/value"]
    return []


def _is_sensitive_env_name(name: str) -> bool:
    """True when an env-var name marks its value as sensitive.

    The ``_FILE``/``_PATH`` suffix is the standard convention for a pointer to
    a mounted secret file rather than a literal, so it passes.
    """
    if name.endswith("_file") or name.endswith("_path"):
        return False
    return any(fragment in name for fragment in _SENSITIVE_NAME_FRAGMENTS)


def _env_var_entries(environment):
    """Yield ``(index, entry)`` for each environment_variable block.

    Checkov wraps attribute values in single-element lists, so the nested
    block arrives as ``[{"compute_type": [...], "environment_variable": [{...}]}]``.
    """
    if not isinstance(environment, list):
        return
    for block in environment:
        if not isinstance(block, dict):
            continue
        entries = block.get("environment_variable")
        if not isinstance(entries, list):
            continue
        for idx, entry in enumerate(entries):
            if isinstance(entry, dict):
                yield idx, entry


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
