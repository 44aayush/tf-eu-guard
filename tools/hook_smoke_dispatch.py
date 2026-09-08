"""PostToolUse hook dispatcher: run smoke checks only when a relevant file was edited.

Claude Code pipes the tool-call JSON to this script on stdin after every
Edit/Write/MultiEdit. A full re-scan on every edit would be slow enough to
train people to ignore the hook — so this reads the edited file path,
maps it to the IaC types it can affect, and shells out to
``tools/smoke_check.py --iac-type <type>`` only on a match.

Exit codes (forwarded to Claude Code): 0 = nothing matched or all checks
passed, 1 = unexpected error, 2 = a smoke check failed (Claude Code shows
stderr to the user even though the edit already completed).

Path mapping:
- ``tf_eu_guard/checkov_runner.py`` / ``tf_eu_guard/cli.py`` — all types.
  These are exactly the class of file that broke terraform_plan in c7e68f6
  while leaving Kubernetes untouched.
- ``tf_eu_guard/mapping/registry-aws.yaml`` (and azure/gcp) — terraform +
  terraform_plan (the AWS registry covers both; plan mode fires the same
  CKV_AWS_* IDs).
- ``tf_eu_guard/mapping/registry-kubernetes.yaml`` — kubernetes only.
- ``tf_eu_guard/mapping/*`` (other files, e.g. a new registry) — terraform +
  terraform_plan (conservative default for mapping changes).
- ``tf_eu_guard/checks/gdpr|nis2/*`` — terraform + terraform_plan (custom
  Terraform checks).
- ``tf_eu_guard/checks/k8s/*`` — kubernetes only.
- ``examples/**`` — the example's directory decides (vulnerable-aws-plan →
  terraform_plan; kubernetes dirs → kubernetes; everything else → terraform).

When adding a new IaC type or example fixture, extend this mapping in the
same commit — the failure mode of skipping it is the same silent-0 the hook
exists to catch.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SMOKE_CHECK = REPO_ROOT / "tools" / "smoke_check.py"

# Make the package importable (conftest.py does the same sys.path insert) so
# the IaC-type list has a single source of truth.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from tf_eu_guard.constants import SUPPORTED_IAC_TYPES  # noqa: E402

ALL_TYPES = list(SUPPORTED_IAC_TYPES)
TERRAFORM_TYPES = ["terraform", "terraform_plan"]


def types_for_path(path: str) -> list[str] | None:
    """Map an edited repo-relative path to the IaC types to smoke-check."""
    p = Path(path)

    # Runner/CLI changes can affect every scan path.
    if p.match("tf_eu_guard/checkov_runner.py") or p.match("tf_eu_guard/cli.py"):
        return ALL_TYPES

    # Registry files: kubernetes.yaml only affects the k8s namespace; every
    # other registry (aws/azure/gcp, or a new one) affects Terraform modes.
    if p.match("tf_eu_guard/mapping/*.yaml"):
        if p.name == "registry-kubernetes.yaml":
            return ["kubernetes"]
        return TERRAFORM_TYPES

    # Custom checks: the k8s/ subdir holds the Kubernetes variant; gdpr/ and
    # nis2/ hold Terraform ones.
    if p.match("tf_eu_guard/checks/k8s/*"):
        return ["kubernetes"]
    if p.match("tf_eu_guard/checks/gdpr/*") or p.match("tf_eu_guard/checks/nis2/*"):
        return TERRAFORM_TYPES
    if p.match("tf_eu_guard/checks/*"):
        # Loader/__init__ or a future check dir — check everything.
        return ALL_TYPES

    # Example fixtures: the example's own directory names its IaC type.
    if p.match("examples/*") or p.match("examples/*/*"):
        top = p.parts[1] if len(p.parts) > 1 else ""
        if "kubernetes" in top:
            return ["kubernetes"]
        if "plan" in top:
            return ["terraform_plan"]
        return ["terraform"]

    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"hook_smoke_dispatch: could not parse tool input JSON: {exc}", file=sys.stderr)
        return 0  # Malformed hook input is never a finding — don't block the user.

    # PostToolUse payload: {"tool_name": ..., "tool_input": {"file_path": ...},
    # "tool_response": ...}. Older MultiEdit used "edits"; accept both.
    tool_input = payload.get("tool_input") or {}
    file_path = (
        tool_input.get("file_path")
        or tool_input.get("path")
        or (tool_input.get("edits") or [{}])[0].get("file_path")
    )
    if not file_path:
        return 0  # Nothing we know how to map — not an error.

    # Only react to paths inside this repo; absolute paths are made relative.
    abs_path = Path(file_path)
    try:
        rel = abs_path.relative_to(REPO_ROOT)
    except ValueError:
        rel = Path(file_path)  # Already repo-relative (or foreign — mapping will miss).

    iac_types = types_for_path(str(rel))
    if not iac_types:
        return 0  # Unrelated edit (README, tests, ...) — stay quiet and fast.

    # One smoke_check.py invocation per IaC type (keeps the "scoped to one
    # --iac-type" contract: each check only scans that type's examples).
    worst_exit = 0
    for iac_type in iac_types:
        print(
            f"hook: smoke-checking {iac_type} (edited: {rel})",
            file=sys.stderr,
        )
        try:
            result = subprocess.run(
                [sys.executable, str(SMOKE_CHECK), "--iac-type", iac_type],
                cwd=REPO_ROOT,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            print(
                f"hook: smoke check for {iac_type} timed out after 300s — "
                f"run 'python3 tools/smoke_check.py --iac-type {iac_type}' manually",
                file=sys.stderr,
            )
            return 1
        worst_exit = max(worst_exit, result.returncode)

    return worst_exit


if __name__ == "__main__":
    sys.exit(main())
