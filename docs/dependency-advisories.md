# Dependency advisory exceptions

The runtime lock is audited in CI with `pip-audit --strict`. Three advisory
IDs currently require bounded exceptions because they arrive through the
Checkov scanner dependency tree:

| Advisory | Locked package | Version | Owner | Review | Expiry |
| --- | --- | --- | --- | --- | --- |
| `PYSEC-2026-3807` | `asteval` | `1.0.6` | tf-eu-guard maintainers | 2026-12-17 | 2027-02-17 |
| `GHSA-9w56-46f6-3qhx` | `asteval` | `1.0.6` | tf-eu-guard maintainers | 2026-12-17 | 2027-02-17 |
| `PYSEC-2026-1325` | `ecdsa` | `0.19.2` | tf-eu-guard maintainers | 2026-12-17 | 2027-02-17 |

The machine-readable source of truth is
[`dependency-exceptions.json`](../dependency-exceptions.json). It records the
owner, rationale, mitigation, review date, expiry date, lock version, and
Checkov provenance for every CI ignore. `tools/check_dependency_exceptions.py`
fails CI when a required field is missing, an exception is expired, a locked
version changes without updating the record, or the workflow ignore list drifts
from the record.

## Resolution test (2026-11-17)

Checkov `3.4.5` is the latest PyPI release (up from the `3.3.29` in the
2026-10-17 record; `3.3.30` and `3.4.0` to `3.4.4` were skipped). It was tested
and is now the pin in `pyproject.toml` and `requirements.lock`:

- Full suite with `TFEG_RUN_CHECKOV=1` on Python 3.12 against an environment
  with `checkov==3.4.5`: 820 passed, 5 skipped. `tools/smoke_check.py
  --iac-type all` passed for all nine examples (terraform, terraform_plan,
  kubernetes).
- The same suite passed on Python 3.11, 3.12 and 3.14 from the new hashed locks
  (`pip install --require-hashes -r requirements.lock -r requirements-dev.lock`
  then `pip install --no-deps -e .`).
- `pip-audit --strict` on `requirements.lock` with the three ignores reports no
  other vulnerability. Without the ignores it reports exactly
  `PYSEC-2026-3807` and `GHSA-9w56-46f6-3qhx` (`asteval` 1.0.6, fix 1.0.9) and
  `PYSEC-2026-1325` (`ecdsa` 0.19.2, no fix version). `requirements-dev.lock`
  and `requirements-ci.lock` audit clean.

Checkov 3.4.5 still declares `asteval==1.0.6` and `ecdsa>=0.19.0,<1.0.0`, so
Checkov continues to pin the vulnerable `asteval`, `ecdsa` stays at its latest
release `0.19.2` without a fix, and all three advisories still apply. The
exceptions stay, with review moved to 2026-12-17 and expiry to 2027-02-17 (the
same one-month review and three-month expiry cadence as before).

Recommendation, not yet acted on: ask upstream Checkov (bridgecrewio/checkov) to
raise the `asteval` pin to 1.0.9 or later, or to relax it to a range. Checkov
evaluates Terraform expressions from the scanned code with `asteval`, so the
fix matters for pull-request scanning. No issue has been opened.

While regenerating the locks, pip-audit also flagged `soupsieve` 2.10 (kept
from the old lock) and `filelock` 4.2.0 (CI tooling lock). Both were moved to
fixed versions (`soupsieve` 4.1.1, `filelock` 4.2.11) rather than excepted,
which is why the runtime lock is resolved from Python 3.11.5.

## Earlier resolution test (2026-10-17)

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
