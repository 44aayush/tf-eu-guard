"""Helpers for values normalized by Checkov."""


def unwrap_checkov_scalar(value):
    """Return the value inside Checkov's single-element list wrapper.

    Checkov may represent a Terraform attribute as a one-item list. Empty
    lists have no scalar value and therefore return ``None``; all other values
    pass through unchanged.
    """
    if isinstance(value, list):
        return value[0] if value else None
    return value
