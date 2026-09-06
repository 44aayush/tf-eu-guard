"""Smoke check: scan a vulnerable/compliant example pair and verify the counts.

This is the regression guard for the failure mode shipped in commit c7e68f6 —
a change that silently produces 0 findings on a real example while unit tests
stay green. Run it standalone:

    python3 tools/smoke_check.py --iac-type terraform_plan
    python3 tools/smoke_check.py --iac-type all

Exit codes: 0 = clean, 1 = unexpected error, 2 = a check failed (findings
outside the expected baseline). Exit 2 is what the Claude Code hook relies on
to surface the failure loudly (stderr from a hook exiting 2 is shown to the
user even after the edit already landed).

Expected counts come from tools/smoke_baselines.json — the same file CI
reads — so there's one source of truth, not two copies that drift apart.
Vulnerable examples must return at least ``min`` findings (and always more
than zero, even if ``min`` is 0); compliant examples must return exactly 0.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO_ROOT / "tools" / "smoke_baselines.json"
#: IaC types with a baseline entry. "all" fans out over every key.
IAC_TYPES = ("terraform", "terraform_plan", "kubernetes")

# CLI flag to pass for each IaC type. "terraform" is the CLI default, but
# pass it explicitly so the invocation is self-documenting in any output.
IAC_TYPE_FLAG = {
    "terraform": ["--iac-type", "terraform"],
    "terraform_plan": ["--iac-type", "terraform_plan"],
    "kubernetes": ["--iac-type", "kubernetes"],
}


def _scan(path: str, iac_type: str) -> int:
    """Run the CLI scan against ``path`` and return the mapped-finding count.

    Raises on any CLI error — an erroring scan is an unexpected failure (exit
    1), not a smoke-check failure (exit 2). This distinction matters: exit 2
    means "the tool ran fine and the finding count is wrong."
    """
    cmd = [
        sys.executable,
        "-m",
        "tf_eu_guard.cli",
        "scan",
        path,
        *IAC_TYPE_FLAG[iac_type],
        "--output",
        "json",
    ]
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        # --output json prints findings on stdout; exit code 0 without
        # --fail-on-* flags even when findings exist.
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"scan of {path} ({iac_type}) exited {result.returncode}: {result.stderr.strip()}"
        )
    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"scan of {path} ({iac_type}) emitted invalid JSON: {exc}") from exc
    if not isinstance(findings, list):
        raise RuntimeError(
            f"scan of {path} ({iac_type}) emitted {type(findings).__name__}, expected a JSON array"
        )
    return len(findings)


def check_iac_type(iac_type: str) -> list[str]:
    """Run all baseline checks for one IaC type; return failure messages."""
    baselines = json.loads(BASELINE_FILE.read_text())
    if iac_type not in baselines:
        raise RuntimeError(
            f"no baseline entry for iac_type '{iac_type}' in {BASELINE_FILE} — "
            f"known types: {', '.join(baselines)}"
        )

    failures = []

    for path, spec in baselines[iac_type].get("vulnerable", {}).items():
        count = _scan(path, iac_type)
        # Guard against the exact shipped bug: a code path that silently
        # returns nothing. min is a floor so legitimate registry/check growth
        # doesn't fail the guard; a vulnerable example must always yield at
        # least ONE finding, even if the baseline's min was set to 0 (per the
        # baselines file's own "and > 0" contract). expected is reported for
        # context.
        floor = max(spec["min"], 1)
        if count < floor:
            failures.append(
                f"vulnerable example {path} ({iac_type}) returned {count} mapped "
                f"findings — expected {spec['expected']} (floor {floor}). "
                f"A near-zero count usually means the scan path is broken, not "
                f"that the example got compliant."
            )
        elif count != spec["expected"]:
            # Within the floor but off the measured count — note it, don't fail.
            print(
                f"note: {path} ({iac_type}) returned {count} findings; "
                f"baseline says {spec['expected']}. If intentional, update "
                f"tools/smoke_baselines.json.",
                file=sys.stderr,
            )

    for path, spec in baselines[iac_type].get("compliant", {}).items():
        count = _scan(path, iac_type)
        if count > spec["max"]:
            failures.append(
                f"compliant example {path} ({iac_type}) returned {count} mapped "
                f"findings — expected {spec['expected']}. Something is firing "
                f"on the compliant fixture."
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--iac-type",
        choices=[*IAC_TYPES, "all"],
        required=True,
        help="Which IaC type's example pair to scan ('all' = every type). "
        "Scope to one type when running interactively — each Checkov scan "
        "takes seconds.",
    )
    args = parser.parse_args()

    types = list(IAC_TYPES) if args.iac_type == "all" else [args.iac_type]

    all_failures = []
    try:
        for iac_type in types:
            all_failures.extend(check_iac_type(iac_type))
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"smoke check error ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1

    if all_failures:
        # Multi-line, specific, with counts — never just "smoke check failed".
        # Claude Code shows this to the user because we exit 2.
        print("SMOKE CHECK FAILED:", file=sys.stderr)
        for failure in all_failures:
            print(f"  - {failure}", file=sys.stderr)
        return 2

    checked = sum(
        len(json.loads(BASELINE_FILE.read_text())[t].get("vulnerable", {}))
        + len(json.loads(BASELINE_FILE.read_text())[t].get("compliant", {}))
        for t in types
    )
    print(f"smoke check OK ({checked} example(s), {', '.join(types)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
