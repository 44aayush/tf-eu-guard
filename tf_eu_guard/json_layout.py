"""The effective ``--json-format`` layout, shared by the reports and provenance."""

import argparse


def resolve_json_format(args: argparse.Namespace | None) -> str:
    """Return the effective ``--json-format``: ``"array"`` unless ``"object"`` was given."""
    return "object" if getattr(args, "json_format", None) == "object" else "array"
