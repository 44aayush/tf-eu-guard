"""Tests for tools/hook_smoke_dispatch.py — the PostToolUse hook dispatcher.

The dispatcher's path→iac-type routing table is what keeps the Claude Code
smoke-check hook honest: a wrong route means a silent-0 regression guard (the
exact failure mode of commit c7e68f6). These tests assert every routing rule
documented in the module docstring and in CONTRIBUTING.md §"Claude Code hook".

Hermetic: routing is pure; ``main()`` tests mock the smoke_check subprocess.
"""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

# tools/ is not a package; put it on sys.path to import its modules (and let
# ``--cov=tools`` measure them).
TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import hook_smoke_dispatch  # noqa: E402

ALL_TYPES = ["terraform", "terraform_plan", "kubernetes"]
TERRAFORM_TYPES = ["terraform", "terraform_plan"]


# --- The routing table, one test per documented rule -----------------------------


def test_runner_and_cli_route_to_all_types():
    """Documented: checkov_runner.py / cli.py -> all types (the class of file
    that broke terraform_plan in c7e68f6 while leaving Kubernetes untouched)."""
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/checkov_runner.py") == ALL_TYPES
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/cli.py") == ALL_TYPES


@pytest.mark.parametrize("registry", ["registry-aws.yaml", "registry-azure.yaml", "registry-gcp.yaml"])
def test_cloud_registries_route_to_terraform_types(registry):
    """Documented: registry-aws/azure/gcp.yaml -> terraform + terraform_plan
    (the same CKV_AWS_*-style IDs fire in both modes)."""
    assert hook_smoke_dispatch.types_for_path(f"tf_eu_guard/mapping/{registry}") == TERRAFORM_TYPES


def test_kubernetes_registry_routes_to_kubernetes_only():
    """Documented: registry-kubernetes.yaml -> kubernetes only."""
    assert (
        hook_smoke_dispatch.types_for_path("tf_eu_guard/mapping/registry-kubernetes.yaml")
        == ["kubernetes"]
    )


def test_unknown_mapping_file_defaults_to_terraform_types():
    """Documented: any other file under mapping/ (e.g. a new registry) ->
    terraform + terraform_plan (conservative default)."""
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/mapping/registry-oci.yaml") == TERRAFORM_TYPES


def test_k8s_checks_route_to_kubernetes():
    """Documented: checks/k8s/* -> kubernetes only."""
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/checks/k8s/secrets_in_code.py") == ["kubernetes"]
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/checks/k8s/__init__.py") == ["kubernetes"]


@pytest.mark.parametrize("subdir", ["gdpr", "nis2"])
def test_terraform_custom_checks_route_to_terraform_types(subdir):
    """Documented: checks/gdpr|nis2/* (Terraform custom checks) -> terraform +
    terraform_plan."""
    assert (
        hook_smoke_dispatch.types_for_path(f"tf_eu_guard/checks/{subdir}/secrets_in_code.py")
        == TERRAFORM_TYPES
    )


def test_checks_loader_routes_to_all_types():
    """Documented: anything else under checks/ (loader/__init__/future dir) ->
    check everything."""
    assert hook_smoke_dispatch.types_for_path("tf_eu_guard/checks/__init__.py") == ALL_TYPES


def test_unrelated_paths_do_not_match():
    """Documented: unrelated edits (README, tests, docs) trigger nothing."""
    for path in ("README.md", "tests/test_cli.py", "docs/gdpr-mapping.md", "pyproject.toml", ""):
        assert hook_smoke_dispatch.types_for_path(path) is None, path


def test_examples_route_by_directory_name():
    """Documented: the example's directory decides — *plan* -> terraform_plan,
    *kubernetes* -> kubernetes, everything else -> terraform."""
    assert hook_smoke_dispatch.types_for_path("examples/vulnerable-aws/main.tf") == ["terraform"]
    assert hook_smoke_dispatch.types_for_path("examples/vulnerable-aws-plan/plan.json") == ["terraform_plan"]
    assert (
        hook_smoke_dispatch.types_for_path("examples/vulnerable-kubernetes/pod.yaml")
        == ["kubernetes"]
    )
    assert hook_smoke_dispatch.types_for_path("examples/compliant-aws/main.tf") == ["terraform"]


def test_absolute_paths_outside_repo_do_not_crash():
    """Paths outside the repo root are not an error — they just don't match."""
    assert hook_smoke_dispatch.types_for_path("/etc/passwd") is None


# --- main() behavior (mocked smoke_check subprocess) ----------------------------


def _payload(**tool_input):
    return json.dumps({"tool_name": "Edit", "tool_input": tool_input})


def _run_main(monkeypatch, stdin_text):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    return hook_smoke_dispatch.main()


def test_main_malformed_json_is_not_an_error(monkeypatch):
    """Malformed hook input is never a finding — don't block the user."""
    assert _run_main(monkeypatch, "not json {") == 0


def test_main_no_file_path_is_quiet(monkeypatch):
    assert _run_main(monkeypatch, _payload()) == 0


def test_main_unrelated_edit_runs_nothing(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0))
    assert _run_main(monkeypatch, _payload(file_path="README.md")) == 0
    assert calls == []


def test_main_runs_one_smoke_check_per_type(monkeypatch, capsys):
    """cli.py routes to all three types -> three smoke_check invocations."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _run_main(monkeypatch, _payload(file_path="tf_eu_guard/cli.py")) == 0
    assert len(calls) == 3
    # each invocation is scoped to exactly one --iac-type
    for cmd in calls:
        assert cmd[cmd.index("--iac-type") + 1] in ALL_TYPES
    assert {cmd[cmd.index("--iac-type") + 1] for cmd in calls} == set(ALL_TYPES)


def test_main_forwards_worst_exit_code(monkeypatch):
    """A failing smoke check (exit 2) must surface as exit 2 from the hook."""
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _run_main(monkeypatch, _payload(file_path="tf_eu_guard/mapping/registry-aws.yaml")) == 2


def test_main_absolute_repo_path_is_made_relative(monkeypatch):
    """Absolute paths inside the repo resolve to their routing rule."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    abs_path = hook_smoke_dispatch.REPO_ROOT / "tf_eu_guard" / "mapping" / "registry-kubernetes.yaml"
    assert _run_main(monkeypatch, _payload(file_path=str(abs_path))) == 0
    assert len(calls) == 1
    assert calls[0][calls[0].index("--iac-type") + 1] == "kubernetes"


# --- CONTRIBUTING.md documents the routing rules ---------------------------------


def test_contributing_documents_the_routing_rules(repo_root: Path):
    """Each routing rule asserted above must also be documented in
    CONTRIBUTING.md — if the routing changes, the docs must change with it."""
    doc = " ".join((repo_root / "CONTRIBUTING.md").read_text().split())
    for claim in (
        "`cli.py`/`checkov_runner.py` → all types",
        "`registry-kubernetes.yaml` → kubernetes only",
        "`examples/vulnerable-aws-plan/**` → terraform_plan",
    ):
        assert claim in doc, f"CONTRIBUTING.md no longer documents: {claim}"
