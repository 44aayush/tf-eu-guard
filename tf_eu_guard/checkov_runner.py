"""Compatibility facade for Checkov execution and JSON handling."""

import tf_eu_guard.checkov.json as _checkov_json
import tf_eu_guard.checkov.process as _checkov_process
from tf_eu_guard.checkov.types import CheckovInputError, CheckovRuntimeError

# Preserve the original module-level names for callers that imported them.
subprocess = _checkov_process.subprocess
_CHECKOV_BOOTSTRAP = _checkov_process.CHECKOV_BOOTSTRAP
_CHECKOV_CONFIG_ENV_VARS = _checkov_process.CHECKOV_CONFIG_ENV_VARS
_checkov_environment = _checkov_process.checkov_environment
_describe_json_shape = _checkov_json.describe_json_shape
_is_within = _checkov_process.is_within
_normalize_checkov_output = _checkov_json.normalize_checkov_output
_parsing_error_message = _checkov_json.parsing_error_message
_reject_unsupported_source_files = _checkov_process.reject_unsupported_source_files
_stderr_tail = _checkov_process.stderr_tail
_trusted_checkov_workdir = _checkov_process.trusted_checkov_workdir
_validate_checkov_output = _checkov_json.validate_checkov_output
_validate_failed_check = _checkov_json.validate_failed_check
_validate_scan_output = _checkov_json.validate_scan_output
_validate_scan_root_symlinks = _checkov_process.validate_scan_root_symlinks
extract_failed_checks = _checkov_json.extract_failed_checks
load_checkov_json = _checkov_json.load_checkov_json
run_checkov = _checkov_process.run_checkov


__all__ = [
    "CheckovInputError",
    "CheckovRuntimeError",
    "extract_failed_checks",
    "load_checkov_json",
    "run_checkov",
]
