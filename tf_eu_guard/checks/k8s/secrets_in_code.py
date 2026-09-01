"""
Custom Checkov check: hardcoded secrets in Kubernetes manifests.

Kubernetes counterpart of ``checks/nis2/secrets_in_code.py``
(EUGUARD_NIS2_001). Two shapes are flagged:

1. Literal values in a ``Secret`` manifest (``data`` — including values that
   are only base64-of-plaintext, i.e. not real secrets management — or
   ``stringData``). A Secret committed to Git is not a secrets-management
   control: it is a credential in version control.
2. A literal ``value:`` in a container's ``env:`` block where a secret is
   clearly expected — detected by the variable naming convention
   (PASSWORD/TOKEN/SECRET/KEY/...), since Kubernetes has no type system to
   declare "this env var is sensitive".

The compliant forms — ``valueFrom.secretKeyRef``, ``valueFrom.configMapKeyRef``
``secretRef`` in ``envFrom``, or an external-secrets-operator-managed Secret
with no in-manifest data — pass.

Same regulatory basis as the Terraform variant: storing secrets in code is
insecure development/maintenance practice under NIS2 Art. 21(2)(e), and where
the secret guards personal data, a confidentiality risk under GDPR
Art. 32(1)(b).
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_container_check import BaseK8sContainerCheck
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check

# Env-var name fragments that mark the value as sensitive.
_SENSITIVE_NAME_FRAGMENTS = (
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_key", "private_key", "credential",
)


class K8sSecretManifestHardcodedSecrets(BaseK8Check):
    """Flag Secret manifests whose data/stringData values are committed literals."""

    def __init__(self):
        name = "Ensure Kubernetes Secrets do not contain hardcoded literal values (use a secrets manager)"
        check_id = "EUGUARD_NIS2_001"
        supported_entities = ("Secret",)
        categories = [CheckCategories.SECRETS]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_entities=supported_entities,
        )

    def scan_spec_conf(self, conf):
        self.evaluated_keys = ["data", "stringData"]
        for field in ("data", "stringData"):
            values = conf.get(field)
            if not isinstance(values, dict):
                continue
            if _values_look_committed(values):
                return CheckResult.FAILED
        return CheckResult.PASSED


class K8sContainerEnvHardcodedSecrets(BaseK8sContainerCheck):
    """Flag literal values in env vars whose names mark them as sensitive."""

    def __init__(self):
        name = "Ensure containers use secretKeyRef instead of literal sensitive env values"
        check_id = "EUGUARD_NIS2_001"
        categories = [CheckCategories.SECRETS]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
        )

    def scan_container_conf(self, metadata, conf):
        env = conf.get("env")
        if not isinstance(env, list):
            return CheckResult.PASSED
        for idx, entry in enumerate(env):
            if not isinstance(entry, dict):
                continue
            if "valueFrom" in entry:
                continue  # secretKeyRef/configMapKeyRef — the compliant form
            name = str(entry.get("name", "")).lower()
            value = entry.get("value")
            if not isinstance(value, str):
                continue  # numeric/boolean values are not secrets
            if not value.strip():
                continue  # set at runtime / kustomize placeholder
            if name.endswith("_file") or name.endswith("_path"):
                # The _FILE / _PATH suffix is the standard convention for a
                # pointer to a mounted secret file, not a literal secret.
                continue
            if any(fragment in name for fragment in _SENSITIVE_NAME_FRAGMENTS):
                self.evaluated_container_keys = [f"env/[{idx}]/value"]
                return CheckResult.FAILED
        return CheckResult.PASSED


def _values_look_committed(values: dict) -> bool:
    """True when any Secret value is a literal (vs. an operator placeholder).

    A Secret managed by external-secrets/sealed-secrets carries no literal
    values in its manifest (empty data, or only non-sensitive sync labels).
    Any present, non-empty literal — in ``data`` (even base64) or
    ``stringData`` — means the credential itself is committed.
    """
    for value in values.values():
        if isinstance(value, str) and value.strip():
            return True
    return False


check = K8sSecretManifestHardcodedSecrets()
check = K8sContainerEnvHardcodedSecrets()
