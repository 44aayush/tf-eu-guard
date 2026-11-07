"""Shared heuristics for detecting literal secret environment variables."""

import re

# Terraform/Checkov can expose the same expression in several forms.  Source
# HCL commonly uses ``${var.password}``, while Checkov's normalised resource
# configuration usually contains ``var.password``.  Resource traversals such
# as ``data.aws_secretsmanager_secret_version.db.secret_string`` and
# ``aws_ssm_parameter.password.value`` are references too, not credentials
# embedded in the configuration.
_REFERENCE_TRAVERSAL = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)+$")
_INTERPOLATION = re.compile(r"\$\{[^{}]+\}")
_REFERENCE_ROOTS = frozenset(
    {
        "count",
        "data",
        "each",
        "local",
        "module",
        "path",
        "self",
        "terraform",
        "var",
    }
)

# Match complete underscore-delimited tokens, not arbitrary substrings: a
# name such as ``MONKEY`` is not a credential merely because it ends in KEY.
_SENSITIVE_TOKENS = frozenset(
    {
        "PASSWORD",
        "PASSWD",
        "PWD",
        "SECRET",
        "TOKEN",
        "KEY",
        "APIKEY",
        "CREDENTIAL",
        "CREDENTIALS",
    }
)
_NON_SECRET_EXACT_NAMES = frozenset({"PWD", "OLDPWD"})
_NON_SECRET_SUFFIXES = (
    "_URL",
    "_ENDPOINT",
    "_NAME",
    "_ARN",
    "_FILE",
    "_PATH",
)


def is_sensitive_env_name(name: str) -> bool:
    """Return whether an environment-variable name strongly suggests a secret.

    Matching is token-based rather than substring-based.  This avoids flagging
    identifiers such as ``SECRET_NAME`` and ``TOKEN_ENDPOINT`` while retaining
    common credential names such as ``DB_PASSWORD`` and ``API_TOKEN``. Suffixes
    commonly used for references or identifiers (``_URL``, ``_ENDPOINT``,
    ``_NAME``, ``_ARN``, ``_ID``, ``_FILE``, and ``_PATH``) are not literals.
    """
    normalized = str(name or "").strip().upper()
    if not normalized or normalized in _NON_SECRET_EXACT_NAMES:
        return False
    tokens = set(re.split(r"[^A-Z0-9]+", normalized))
    sensitive = bool(tokens & _SENSITIVE_TOKENS) or any(
        compound in normalized for compound in ("APIKEY", "ACCESS_KEY", "PRIVATE_KEY")
    )
    if normalized.endswith(_NON_SECRET_SUFFIXES):
        return False
    # A generic identifier is not a secret; names with an explicit credential
    # token (for example AWS_ACCESS_KEY_ID) remain sensitive.
    if normalized.endswith("_ID") and not sensitive:
        return False
    return sensitive


def is_reference_value(value: object) -> bool:
    """Return whether a Terraform value is an interpolation or traversal.

    Checkov may strip the ``${...}`` wrapper while building a resource
    configuration, so both wrapped and normalised forms are accepted.  A
    dotted Terraform traversal covers ``data.*``, ``var.*`` and managed
    resource references without requiring a provider-specific allowlist.
    Blank and non-string values are not references; callers can then treat
    them as undecidable rather than as hardcoded secrets.
    """
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if not normalized:
        return False
    if _INTERPOLATION.fullmatch(normalized) or _INTERPOLATION.search(normalized):
        return True
    if not _REFERENCE_TRAVERSAL.fullmatch(normalized):
        return False
    root = normalized.split(".", 1)[0]
    # Provider resource types use Terraform's ``provider_type`` naming (for
    # example ``aws_ssm_parameter``); explicit Terraform namespaces cover the
    # other common traversal forms.
    return root in _REFERENCE_ROOTS or "_" in root


def is_literal_secret_value(value: object) -> bool:
    """Return whether ``value`` is a non-empty literal secret.

    This is the shared predicate for database/cache secret arguments and
    CodeBuild plaintext sensitive environment variables.  References are safe
    configuration indirections; any other non-empty string is a literal.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    return not is_reference_value(value)


def is_literal_env_value(value: object) -> bool:
    """Return whether an env value is a non-empty literal, not a URL."""
    if not isinstance(value, str) or not is_literal_secret_value(value):
        return False
    return not value.strip().lower().startswith(("http://", "https://"))
