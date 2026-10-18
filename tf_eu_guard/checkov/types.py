"""Shared Checkov exception types."""


class CheckovRuntimeError(RuntimeError):
    """Raised when Checkov fails or does not return parseable JSON."""


class CheckovInputError(ValueError):
    """Raised when a user-supplied Checkov JSON path cannot be read."""
