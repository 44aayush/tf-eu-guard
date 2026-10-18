"""Exception classification and presentation for the CLI."""

import json
import sys

from tf_eu_guard.constants import EXIT_INVALID_INPUT, EXIT_RUNTIME_FAILURE
from tf_eu_guard.mapping.loader import RegistryValidationError


def exit_code_for(error: Exception) -> int:
    """Map an exception to the documented invalid-input or runtime exit code."""
    # The registry ships with the tool, so a malformed registry is a runtime
    # failure rather than invalid user input.
    if isinstance(error, RegistryValidationError):
        return EXIT_RUNTIME_FAILURE

    if isinstance(error, (ValueError, json.JSONDecodeError, FileNotFoundError)):
        return EXIT_INVALID_INPUT
    return EXIT_RUNTIME_FAILURE


def handle_scan_error(error: Exception) -> int:
    """Print a scan error and map it to the documented exit code."""
    code = exit_code_for(error)
    label = (
        "invalid input/configuration"
        if code == EXIT_INVALID_INPUT
        else "scanner/runtime failure"
    )
    detail = str(error)
    stderr = getattr(error, "stderr", None)
    if stderr:
        detail += f"\nCheckov stderr:\n{stderr.rstrip()}"
    print(f"Error ({label}): {detail}", file=sys.stderr)
    return code
