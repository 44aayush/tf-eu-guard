"""Neutralise control characters in strings that come from the scanned checkout.

Resource names, file paths and similar values reach the terminal and the CI log
verbatim. A newline followed by ``::error::`` forges a GitHub Actions annotation and
ESC sequences repaint the terminal; ``rich.markup.escape`` covers neither. Characters
are escaped, never dropped, so no value is hidden or truncated.
"""

import re

_UNSAFE = re.compile("[\\x00-\\x08\\x0a-\\x1f\\x7f-\\x9f\u202a-\u202e\u2066-\u2069]")


def _replace(match: re.Match[str]) -> str:
    char = match.group()
    if char == "\n":
        return "\\n"
    if char == "\r":
        return "\\r"
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def sanitize(value: object) -> str:
    """Return ``value`` as text with control and bidi characters escaped."""
    if value is None:
        return ""
    return _UNSAFE.sub(_replace, str(value))
