"""Shared heuristics for detecting literal secret environment variables."""

import re

# Checkov hands the check unresolved Terraform expressions as text.  It strips
# a lone ``"${var.x}"`` wrapper down to ``var.x`` and rewrites ``try(var.x, null)``
# as ``try(var.x,None)``, but keeps ``prod-${var.env}-Hunter2`` verbatim, so the
# predicate has to cope with bare expressions, wrapped ones and mixed strings.
_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_INDEX = r"\[[^\[\]]*\]"
_TRAVERSAL = re.compile(rf"^{_IDENT}(?:\.{_IDENT}|{_INDEX})+$")
_SEGMENT = re.compile(rf"\.{_IDENT}|{_INDEX}")
_FUNCTION_CALL = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\(.*\)(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[^\[\]]*\])*$", re.DOTALL
)
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
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
# ``aws_db_instance``-shaped provider resource type: lowercase, with an underscore.
_RESOURCE_TYPE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+$")
# A reference embedded in a larger expression (function arguments).
_EMBEDDED_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_.\-])(?:(?:"
    + "|".join(sorted(_REFERENCE_ROOTS))
    + r")\.[A-Za-z_]|[a-z][a-z0-9]*_[a-z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_]|\.[A-Za-z_][A-Za-z0-9_-]*\[))"
)


def _split_interpolations(text: str) -> tuple[str, list[str]] | None:
    """Split ``text`` into (literal text outside ``${...}``, interpolation bodies).

    Returns ``None`` when there is no interpolation or it is unbalanced.
    """
    literal: list[str] = []
    bodies: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("${", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            if depth:
                return None
            bodies.append(text[i + 2 : j - 1].strip())
            i = j
        else:
            literal.append(text[i])
            i += 1
    if not bodies:
        return None
    return "".join(literal), bodies


def _is_reference_expression(expr: str) -> bool:
    """Return whether a bare HCL expression is a traversal or function over references."""
    expr = expr.strip()
    if not expr:
        return False
    if _TRAVERSAL.fullmatch(expr):
        root = re.match(_IDENT, expr).group(0)  # type: ignore[union-attr]
        if root in _REFERENCE_ROOTS:
            return True
        # Outside Terraform namespaces a traversal must look like a resource
        # address: a ``provider_type`` root and at least three segments
        # (type, name, attribute; an index counts as a segment).  This rejects
        # literals such as ``db_admin.Password1``.
        segments = 1 + len(_SEGMENT.findall(expr))
        return bool(_RESOURCE_TYPE.fullmatch(root)) and segments >= 3
    if _FUNCTION_CALL.fullmatch(expr):
        return bool(_EMBEDDED_REFERENCE.search(_QUOTED.sub('""', expr)))
    return False


# Match complete underscore-delimited tokens, not arbitrary substrings: a
# name such as ``MONKEY`` is not a credential merely because it ends in KEY.
_SENSITIVE_TOKENS = frozenset(
    {
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PASSPHRASE",
        "DSN",
        "PAT",
        "WEBHOOK",
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
# Names that contain a sensitive token but are clearly not secrets: public
# keys, key-name prefixes, lifetimes/lengths and DynamoDB-style key schema
# attributes.  ``*_KEY_ID`` is deliberately NOT here (AWS_ACCESS_KEY_ID stays
# sensitive); the conservative choice is to exclude only what is unambiguous.
_NON_SECRET_NAME_SUFFIXES = (
    "PUBLIC_KEY",
    "_KEY_PREFIX",
    "_TTL",
    "_LENGTH",
    "PARTITION_KEY",
    "SORT_KEY",
    "HASH_KEY",
    "RANGE_KEY",
)
_SENSITIVE_COMPOUNDS = ("CONNECTION_STRING", "CONN_STR", "CONNECTIONSTRING")
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
    sensitive = sensitive or any(c in normalized for c in _SENSITIVE_COMPOUNDS)
    if normalized.endswith(_NON_SECRET_SUFFIXES) or normalized.endswith(_NON_SECRET_NAME_SUFFIXES):
        return False
    # A generic identifier is not a secret; names with an explicit credential
    # token (for example AWS_ACCESS_KEY_ID) remain sensitive.
    if normalized.endswith("_ID") and not sensitive:
        return False
    return sensitive


def is_reference_value(value: object) -> bool:
    """Return whether a Terraform value is a pure reference (no literal text).

    Accepted: ``var.x``, resource/data traversals (with ``[0]`` / ``["k"]``
    indexes), function calls whose arguments contain a reference
    (``jsondecode(data.x.y.z)["k"]``, ``try(var.pw, null)``), and strings made
    only of interpolations of those (``"${var.a}${var.b}"``).  A string with
    literal text outside its interpolations (``prod-${var.env}-Hunter2``) is a
    literal.  Blank and non-string values are not references.
    """
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if not normalized:
        return False
    parts = _split_interpolations(normalized)
    if parts is not None:
        literal, bodies = parts
        if literal.strip():
            return False
        return all(_is_reference_expression(body) for body in bodies)
    return _is_reference_expression(normalized)


def is_literal_secret_value(value: object) -> bool:
    """Return whether ``value`` is a non-empty literal secret.

    This is the shared predicate for database/cache secret arguments and
    CodeBuild plaintext sensitive environment variables.  References are safe
    configuration indirections; any other non-empty string is a literal.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    return not is_reference_value(value)


# ``scheme://user:password@host`` with a non-empty password.
_CREDENTIAL_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/\s:@]*:[^/\s@]+@\S+", re.ASCII)
_SLACK_WEBHOOK = re.compile(r"^https://hooks\.slack\.com/(?:services|workflows|triggers)/\S+", re.I)


def has_embedded_credentials(value: object) -> bool:
    """Return whether a literal value carries a secret regardless of its name.

    Matches ``scheme://user:password@host`` (non-empty password, including
    ``https://user:token@host``) and Slack incoming-webhook URLs, whose path
    is itself the credential.  References (``${...}``, ``$(VAR)``) and URLs
    without a password do not match.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or "$(" in text or "${" in text:
        return False
    return bool(_CREDENTIAL_URL.match(text) or _SLACK_WEBHOOK.match(text))


def is_literal_env_value(value: object) -> bool:
    """Return whether an env value is a non-empty literal, not a plain URL.

    Plain ``http(s)`` URLs are endpoint configuration and exempt, unless they
    carry credentials (see :func:`has_embedded_credentials`).
    """
    if not isinstance(value, str) or not is_literal_secret_value(value):
        return False
    if has_embedded_credentials(value):
        return True
    return not value.strip().lower().startswith(("http://", "https://"))


def is_secret_env_variable(name: object, value: object) -> bool:
    """Return whether an env var (name, value) is a plaintext committed secret.

    A value with embedded credentials is a secret under any name.  Otherwise
    the name must be sensitive and the value a non-empty literal.
    """
    if has_embedded_credentials(value):
        return True
    text = str(name or "")
    if not is_sensitive_env_name(text):
        return False
    # A DSN is an https URL that embeds its key, so the plain-URL exemption
    # does not apply to it.
    if "DSN" in re.split(r"[^A-Z0-9]+", text.upper()):
        return is_literal_secret_value(value)
    return is_literal_env_value(value)
