"""Shared heuristics for detecting literal secret environment variables."""

import re

# Match complete underscore-delimited tokens, not arbitrary substrings: a
# name such as ``MONKEY`` is not a credential merely because it ends in KEY.
_SENSITIVE_TOKENS = frozenset({
    "PASSWORD",
    "PASSWD",
    "PWD",
    "SECRET",
    "TOKEN",
    "KEY",
    "APIKEY",
    "CREDENTIAL",
    "CREDENTIALS",
})
_NON_SECRET_EXACT_NAMES = frozenset({"PWD", "OLDPWD"})
_NON_SECRET_SUFFIXES = (
    "_URL", "_ENDPOINT", "_NAME", "_ARN", "_FILE", "_PATH",
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
        compound in normalized
        for compound in ("APIKEY", "ACCESS_KEY", "PRIVATE_KEY")
    )
    if normalized.endswith(_NON_SECRET_SUFFIXES):
        return False
    # A generic identifier is not a secret; names with an explicit credential
    # token (for example AWS_ACCESS_KEY_ID) remain sensitive.
    if normalized.endswith("_ID") and not sensitive:
        return False
    return sensitive


def is_literal_env_value(value: object) -> bool:
    """Return whether an env value is a non-empty literal, not a URL."""
    if not isinstance(value, str) or not value.strip():
        return False
    return not value.strip().lower().startswith(("http://", "https://"))
