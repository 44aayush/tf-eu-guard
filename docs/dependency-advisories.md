# Dependency advisory exceptions

The runtime lock is audited in CI with `pip-audit --strict`. Three advisory
IDs currently require bounded exceptions because they arrive through the
Checkov scanner dependency tree:

| Advisory | Locked package | Version | Owner | Review | Expiry |
| --- | --- | --- | --- | --- | --- |
| `PYSEC-2026-3807` | `asteval` | `1.0.6` | tf-eu-guard maintainers | 2026-11-17 | 2027-01-17 |
| `GHSA-9w56-46f6-3qhx` | `asteval` | `1.0.6` | tf-eu-guard maintainers | 2026-11-17 | 2027-01-17 |
| `PYSEC-2026-1325` | `ecdsa` | `0.19.2` | tf-eu-guard maintainers | 2026-11-17 | 2027-01-17 |

The machine-readable source of truth is
[`dependency-exceptions.json`](../dependency-exceptions.json). It records the
owner, rationale, mitigation, review date, expiry date, lock version, and
Checkov provenance for every CI ignore. `tools/check_dependency_exceptions.py`
fails CI when a required field is missing, an exception is expired, a locked
version changes without updating the record, or the workflow ignore list drifts
from the record.

## Resolution test (2026-10-17)

The latest Checkov release available from PyPI was `3.3.29`, the version already
in `requirements.lock`; no newer Checkov release was available to test. Its
metadata declares `asteval==1.0.6` and `ecdsa>=0.19.0,<1.0.0`. The latest
available `asteval` is `1.0.10`, and pip-audit identifies `1.0.9` as the fix for
the two asteval advisories, but that version cannot be substituted while
retaining Checkov's exact dependency contract. The latest available `ecdsa`
is `0.19.2`, and pip-audit reports no fix version for `PYSEC-2026-1325`.

The exception is therefore intentionally bounded rather than hidden: the lock
and the generated CycloneDX SBOM both retain the actual Checkov dependency
versions, CI names each ignored advisory explicitly, and the expiry check
requires a deliberate refresh or removal before 2027-01-17.
