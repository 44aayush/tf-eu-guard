"""Exception classification and presentation for the CLI."""

import json
import sys

from tf_eu_guard.checkov.types import CheckovInputError, CheckovRuntimeError
from tf_eu_guard.constants import EXIT_INVALID_INPUT, EXIT_RUNTIME_FAILURE
from tf_eu_guard.mapping.loader import RegistryValidationError
from tf_eu_guard.reporting.untrusted import sanitize


class OutputWriteError(Exception):
    """A report could not be written or encoded to its destination.

    Raised by the CLI around report rendering (``OSError`` on a file or
    stdout, ``UnicodeEncodeError`` on a narrow-encoding stream). There is no
    dedicated I/O exit code, so it maps to the documented "invalid
    invocation or configuration" code: the destination the user chose
    (``--output-file``, ``--output-dir``, the terminal encoding) is unusable,
    which is not a scanner failure.
    """


#: Exception types that mean the user's input or invocation was unusable.
_INVALID_INPUT_ERRORS = (
    CheckovInputError,
    json.JSONDecodeError,
    FileNotFoundError,
    UnicodeDecodeError,
    OutputWriteError,
)


def exit_code_for(error: Exception) -> int:
    """Map an exception to the documented invalid-input or runtime exit code."""
    # The registry ships with the tool, so a malformed registry is a runtime
    # failure rather than invalid user input (it is a ValueError subclass).
    if isinstance(error, (RegistryValidationError, CheckovRuntimeError)):
        return EXIT_RUNTIME_FAILURE
    # An encode failure outside output writing is an internal bug, not input.
    if isinstance(error, UnicodeEncodeError):
        return EXIT_RUNTIME_FAILURE
    if isinstance(error, _INVALID_INPUT_ERRORS):
        return EXIT_INVALID_INPUT
    # Remaining ValueErrors are raised by explicit argument validation
    # (unsupported iac_type, wrong target kind, bad region list).
    if isinstance(error, ValueError):
        return EXIT_INVALID_INPUT
    return EXIT_RUNTIME_FAILURE


def handle_scan_error(error: Exception) -> int:
    """Print a scan error and map it to the documented exit code."""
    code = exit_code_for(error)
    if isinstance(error, OutputWriteError):
        label = "output could not be written"
    elif code == EXIT_INVALID_INPUT:
        label = "invalid input/configuration"
    else:
        label = "scanner/runtime failure"
    detail = str(error)
    stderr = getattr(error, "stderr", None)
    if stderr:
        # Checkov stderr echoes scanned content: indent so no line starts with "::".
        relayed = "\n".join(f"  {sanitize(line)}" for line in str(stderr).rstrip().splitlines())
        detail += f"\nCheckov stderr:\n{relayed}"
    print(f"Error ({label}): {detail}", file=sys.stderr)
    return code
