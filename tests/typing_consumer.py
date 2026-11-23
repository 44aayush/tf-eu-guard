"""Type-check consumer for the public API; run with mypy, not collected by pytest."""

from tf_eu_guard import ScanResult, scan

result: ScanResult = scan(checkov_json="report.json", framework="gdpr")
count: int = len(result.findings) + len(result.requirements)
