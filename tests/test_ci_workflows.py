"""Static checks for action.yml, the workflows, Dependabot and the sdist config.

These parse the files with PyYAML (and the raw text where YAML comments matter)
so a hardening flag or a pin cannot be dropped silently.
"""

import os
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"

USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+(\.\d+){0,2}\s*$")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _scan_step_run() -> str:
    steps = _load(ACTION)["runs"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "scan")


def _docker_run_block(run: str) -> str:
    start = run.index("docker run --rm")
    end = run.index('"${args[@]}"', start)
    return run[start:end]


def test_action_docker_run_is_hardened():
    block = _docker_run_block(_scan_step_run())
    for flag in (
        "--network none",
        "--read-only",
        "--tmpfs /tmp",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
    ):
        assert flag in block, flag
    # The scanned workspace is read-only at its host path; only /out is writable.
    assert '-v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro"' in block
    assert '-w "$GITHUB_WORKSPACE"' in block
    assert '-v "$out_host:/out"' in block
    assert ":/workspace" not in block
    assert ":rw" not in block
    # Python/Checkov need a writable HOME on a read-only root filesystem.
    assert "HOME=/tmp" in block


def test_action_writes_reports_outside_the_workspace_mount():
    run = _scan_step_run()
    assert '--output-dir "$out_dir_path"' in run
    assert "/out/tf-eu-guard.sarif" in run
    assert "--output-file /workspace/" not in run
    assert 'cp -R --remove-destination "$out_host"/. "$GITHUB_WORKSPACE"/' in run


def test_action_pulls_ghcr_image_then_falls_back_to_local_build():
    run = _scan_step_run()
    assert "ghcr.io/44aayush/tf-eu-guard:${ACTION_REF}" in run
    assert run.index("docker pull") < run.index("docker build")
    assert "image" in _load(ACTION)["inputs"]


def test_every_uses_is_pinned_to_a_sha_with_a_version_comment():
    files = [ACTION, *sorted(WORKFLOWS.glob("*.yml"))]
    seen = 0
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_LINE.match(line)
            if not match:
                continue
            ref = match.group("ref")
            if ref.startswith("./"):
                continue  # local action or reusable workflow in this repository
            seen += 1
            where = f"{path.name}:{number}"
            assert SHA_PIN.match(ref), f"{where}: not pinned to a 40-hex SHA: {ref}"
            assert VERSION_COMMENT.match(match.group("rest")), f"{where}: missing '# vX.Y.Z'"
    assert seen >= 10


def test_upload_sarif_is_codeql_action_v4():
    text = ACTION.read_text(encoding="utf-8")
    match = re.search(r"github/codeql-action/upload-sarif@[0-9a-f]{40} # v(\d+)\.", text)
    assert match, "upload-sarif pin with a version comment not found"
    assert match.group(1) == "4"


def test_readme_example_pins_match_the_workflow_pins():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    pin = re.search(r"actions/checkout@([0-9a-f]{40}) # (v[\d.]+)", ci)
    assert pin
    for found in re.finditer(r"actions/checkout@([0-9a-f]{40}) # (v[\d.]+)", readme):
        assert found.groups() == pin.groups()


def test_publish_requires_tests_and_main_ancestry_before_building():
    workflow = _load(WORKFLOWS / "publish.yml")
    jobs = workflow["jobs"]
    assert jobs["tests"]["uses"] == "./.github/workflows/ci.yml"
    for name in ("build", "image"):
        assert "tests" in jobs[name]["needs"]
        assert "verify-tag" in jobs[name]["needs"]
    verify = jobs["verify-tag"]
    checkout = next(s for s in verify["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0
    commands = "\n".join(step.get("run", "") for step in verify["steps"])
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in commands
    # ci.yml must be callable for the reuse above.
    assert "workflow_call" in _load(WORKFLOWS / "ci.yml")[True]


def test_image_job_publishes_with_provenance_and_minimal_permissions():
    job = _load(WORKFLOWS / "publish.yml")["jobs"]["image"]
    assert job["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    uses = [step.get("uses", "") for step in job["steps"]]
    build = next(
        s
        for s in job["steps"]
        if s.get("uses", "").startswith("docker/build-push-action") and s["with"]["push"] is True
    )
    assert build["with"]["sbom"] is True
    assert str(build["with"]["provenance"]).startswith("mode=")
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses)
    assert "ghcr.io" in _load(WORKFLOWS / "publish.yml")["jobs"]["image"]["env"]["REGISTRY"]


def _publish_image_steps() -> list[dict]:
    return _load(WORKFLOWS / "publish.yml")["jobs"]["image"]["steps"]


def _is_build_push(step: dict) -> bool:
    return step.get("uses", "").startswith("docker/build-push-action@")


def _trivy_scan_index(steps: list[dict]) -> int:
    return next(i for i, s in enumerate(steps) if re.search(r"trivy\"? image", s.get("run", "")))


def test_publish_image_is_scanned_before_push():
    steps = _publish_image_steps()
    scan_at = _trivy_scan_index(steps)
    run = steps[scan_at]["run"]
    for flag in (
        "--exit-code 1",
        "--severity HIGH,CRITICAL",
        "--ignore-unfixed",
        "--ignorefile .trivyignore.yaml",
    ):
        assert flag in run
    push_at = next(
        i for i, s in enumerate(steps) if _is_build_push(s) and s["with"]["push"] is True
    )
    assert scan_at < push_at


def test_publish_trivy_pin_matches_ci():
    ci_steps = _ci_jobs()["image-scan"]["steps"]
    ci_install = next(s for s in ci_steps if "TRIVY_VERSION" in s.get("env", {}))
    install = next(s for s in _publish_image_steps() if "TRIVY_VERSION" in s.get("env", {}))
    assert install["env"]["TRIVY_VERSION"] == ci_install["env"]["TRIVY_VERSION"]
    assert install["env"]["TRIVY_SHA256"] == ci_install["env"]["TRIVY_SHA256"]
    assert "sha256sum --check --strict" in install["run"]


def test_publish_scan_build_does_not_push():
    steps = _publish_image_steps()
    scan_at = _trivy_scan_index(steps)
    scan_run = steps[scan_at]["run"]
    local = [s for s in steps[:scan_at] if _is_build_push(s)]
    assert len(local) == 1
    assert local[0]["with"]["push"] is False
    assert local[0]["with"]["load"] is True
    assert local[0]["with"]["tags"].strip() in scan_run


def test_dependabot_covers_docker_base_image():
    config = _load(ROOT / ".github" / "dependabot.yml")
    ecosystems = {u["package-ecosystem"]: u for u in config["updates"]}
    assert {"github-actions", "pip", "docker"} <= set(ecosystems)
    assert ecosystems["docker"]["directory"] == "/"


def test_ci_matrix_includes_windows_and_macos():
    matrix = _load(WORKFLOWS / "ci.yml")["jobs"]["test"]["strategy"]["matrix"]
    systems = {entry["os"] for entry in matrix["include"]}
    assert "windows-latest" in systems
    assert "macos-latest" in systems


def test_ci_lint_runs_the_same_commands_as_the_dev_hook():
    lint = _load(WORKFLOWS / "ci.yml")["jobs"]["lint"]
    commands = "\n".join(step.get("run", "") for step in lint["steps"])
    hook = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    for command in (
        "ruff check .",
        "ruff format --check .",
        "mypy --ignore-missing-imports tf_eu_guard tools",
    ):
        assert command in commands
        assert command in hook


def test_sdist_uses_an_explicit_include_list():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    include = set(sdist["include"])
    assert {"/tf_eu_guard", "/tests", "/README.md", "/LICENSE", "/pyproject.toml"} <= include
    for excluded in ("/docs", "/examples", "/.github"):
        assert excluded not in include
    assert ".venv/" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_dependency_exceptions_carry_reachability_notes():
    import json

    data = json.loads((ROOT / "dependency-exceptions.json").read_text(encoding="utf-8"))
    for record in data["exceptions"]:
        assert record["reachability"].strip(), record["advisory"]
        if record["package"] == "asteval":
            assert "variable" in record["reachability"]
            assert "--network none" in record["reachability"]


# --- Hashed locks, lock-check and Python alignment (T-26, T-27) ---------------

LOCK_FILES = ("requirements.lock", "requirements-dev.lock", "requirements-ci.lock")


def _ci_jobs() -> dict:
    return _load(WORKFLOWS / "ci.yml")["jobs"]


def _job_commands(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_ci_workflow_keeps_workflow_call():
    on = _load(WORKFLOWS / "ci.yml")[True]  # PyYAML reads the bare key `on` as True
    assert "workflow_call" in on


def test_ci_jobs_install_from_hashed_locks_without_resolving():
    jobs = _ci_jobs()
    for name in ("lint", "test"):
        commands = _job_commands(jobs[name])
        assert (
            "pip install --require-hashes -r requirements.lock -r requirements-dev.lock" in commands
        ), name
        assert "pip install --no-deps -e ." in commands, name
    commands = _job_commands(jobs["example-scan"])
    assert "pip install --require-hashes -r requirements.lock" in commands
    assert "pip install --no-deps -e ." in commands
    # No job may resolve dependencies from PyPI at install time again.
    for name, job in jobs.items():
        for line in _job_commands(job).splitlines():
            assert 'pip install -e ".[dev]"' not in line, name
            assert line.strip() != "pip install -e .", name


def _git_index_mode(rel_path: str) -> str:
    """Mode git records for a file (the Linux CI checkout honors it).

    Filesystem exec bits do not exist on Windows, so the index is the source of
    truth. Skips when git or a git checkout is unavailable (e.g. an sdist).
    """
    if shutil.which("git") is None:
        pytest.skip("git is not available")
    result = subprocess.run(
        ["git", "ls-files", "-s", "--", rel_path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        pytest.skip("not a git checkout (or file untracked); cannot read index mode")
    return result.stdout


def test_git_index_mode_detects_non_executable(monkeypatch):
    # Red proof: a 100644 index entry must fail the executable-bit assertion.
    fake = subprocess.CompletedProcess([], 0, stdout="100644 abc 0\tx.sh\n", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
    assert not _git_index_mode("x.sh").startswith("100755")


def test_lock_check_job_regenerates_locks_and_fails_on_diff():
    job = _ci_jobs()["lock-check"]
    commands = _job_commands(job)
    assert "pip install --require-hashes -r requirements-ci.lock" in commands
    assert "tools/compile-locks.sh" in commands
    assert "git diff --exit-code" in commands
    for lock in LOCK_FILES:
        assert lock in commands
    assert _git_index_mode("tools/compile-locks.sh").startswith("100755")
    for step in job["steps"]:
        if "uses" in step:
            assert SHA_PIN.match(step["uses"]), step["uses"]


def test_compile_script_covers_every_lock_and_contributing_documents_it():
    script = (ROOT / "tools" / "compile-locks.sh").read_text(encoding="utf-8")
    for lock in LOCK_FILES:
        assert lock in script
    assert "--generate-hashes" in script and "--universal" in script
    assert "tools/compile-locks.sh" in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def test_every_lock_requirement_carries_hashes():
    for lock in LOCK_FILES:
        text = (ROOT / lock).read_text(encoding="utf-8")
        # Join continuation lines, then check each requirement entry.
        entries = [
            e for e in text.replace("\\\n", " ").splitlines() if re.match(r"^[A-Za-z0-9]", e)
        ]
        assert entries, lock
        for entry in entries:
            assert "==" in entry, (lock, entry)
            assert "--hash=sha256:" in entry, (lock, entry)


def test_dev_lock_matches_the_dev_extra_and_is_constrained_by_the_runtime_lock():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extra = config["project"]["optional-dependencies"]["dev"]

    def names(requirements) -> set[str]:
        return {re.split(r"[<>=!~\[ ]", r.strip(), maxsplit=1)[0].lower() for r in requirements}

    dev_in = [
        line.strip()
        for line in (ROOT / "requirements-dev.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith(("#", "-"))
    ]
    assert names(dev_in) == names(extra)
    assert "-c requirements.lock" in (ROOT / "requirements-dev.in").read_text(encoding="utf-8")

    def pins(lock: str) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        text = (ROOT / lock).read_text(encoding="utf-8")
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", text, re.MULTILINE):
            found.setdefault(match.group(1).lower().replace("_", "-"), set()).add(match.group(2))
        return found

    runtime, dev = pins("requirements.lock"), pins("requirements-dev.lock")
    shared = runtime.keys() & dev.keys()
    assert shared  # e.g. typing-extensions
    for name in shared:
        assert dev[name] <= runtime[name], name


def _dockerfile_python() -> tuple[int, int]:
    first = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()[0]
    match = re.match(r"FROM python:(\d+)\.(\d+)", first)
    assert match, first
    return int(match.group(1)), int(match.group(2))


def _lock_python_version(lock: str) -> tuple[int, ...]:
    header = "\n".join((ROOT / lock).read_text(encoding="utf-8").splitlines()[:3])
    match = re.search(r"--python-version (\d+(?:\.\d+)+)", header)
    assert match, f"{lock} header does not record its Python version"
    return tuple(int(part) for part in match.group(1).split("."))


def test_lock_python_versions_match_the_dockerfile():
    docker = _dockerfile_python()
    # The image-only tooling lock is resolved for exactly the image's Python.
    assert _lock_python_version("requirements-ci.lock")[:2] == docker
    # Runtime and dev locks are universal and start at the oldest supported
    # Python, so the image's interpreter must be inside their range.
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "requires-python"
    ]
    minimum = tuple(int(p) for p in re.search(r">=(\d+\.\d+)", requires).group(1).split("."))
    for lock in ("requirements.lock", "requirements-dev.lock"):
        assert "--universal" in (ROOT / lock).read_text(encoding="utf-8").splitlines()[1]
        version = _lock_python_version(lock)
        assert version[:2] == minimum, lock
        assert version[:2] <= docker, lock


# --- Workflow hygiene (T-36, T-39) ---------------------------------------------


def _workflows() -> dict[str, dict]:
    return {path.name: _load(path) for path in sorted(WORKFLOWS.glob("*.yml"))}


def test_every_job_has_a_timeout_except_reusable_workflow_calls():
    for name, workflow in _workflows().items():
        for job_id, job in workflow["jobs"].items():
            if "uses" in job:
                assert "timeout-minutes" not in job  # not allowed on a workflow call
                continue
            assert isinstance(job.get("timeout-minutes"), int), f"{name}:{job_id}"
            assert 1 <= job["timeout-minutes"] <= 60, f"{name}:{job_id}"


def test_every_job_has_an_explicit_name_equal_to_its_id_or_matrix_form():
    # Explicit names keep required-status-check names stable and satisfy zizmor.
    for name, workflow in _workflows().items():
        for job_id, job in workflow["jobs"].items():
            assert "name" in job, f"{name}:{job_id}"
            if "strategy" not in job:
                assert job["name"] == job_id, f"{name}:{job_id}"


def test_workflows_limit_concurrency_and_only_cancel_pull_requests():
    for name, workflow in _workflows().items():
        concurrency = workflow["concurrency"]
        assert "github.ref" in concurrency["group"], name
        cancel = concurrency["cancel-in-progress"]
        if name == "publish.yml":
            assert cancel is False  # never cancel a release
        else:
            assert cancel == "${{ github.event_name == 'pull_request' }}", name
    groups = [w["concurrency"]["group"] for w in _workflows().values()]
    # publish.yml calls ci.yml; a shared group would deadlock the call.
    assert len(set(groups)) == len(groups)


def test_every_permissions_block_is_commented():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if line.strip() != "permissions:":
                continue
            above = lines[number - 1].strip()
            assert above.startswith("#"), f"{path.name}:{number + 1}: undocumented permissions"
            # Write scopes additionally explain themselves inline.
            for entry in lines[number + 1 :]:
                if not entry.startswith(" " * (len(line) - len(line.lstrip()) + 2)):
                    break
                if entry.split(":")[1].strip().startswith("write"):
                    assert "#" in entry, f"{path.name}: write scope without a comment: {entry}"


def test_no_template_expressions_inside_run_scripts():
    scripts = []
    for name, workflow in _workflows().items():
        for job_id, job in workflow["jobs"].items():
            scripts += [
                (f"{name}:{job_id}", step["run"]) for step in job.get("steps", []) if "run" in step
            ]
    scripts += [
        ("action.yml", step["run"]) for step in _load(ACTION)["runs"]["steps"] if "run" in step
    ]
    assert scripts
    for where, script in scripts:
        assert "${{" not in script, f"{where}: pass the value through env instead"


def test_e2e_passes_gated_outcome_through_env():
    text = (WORKFLOWS / "action-e2e.yml").read_text(encoding="utf-8")
    assert "GATED_OUTCOME: ${{ steps.gated.outcome }}" in text
    assert "${GATED_OUTCOME}" in text


def test_lint_job_runs_zizmor_and_actionlint_pinned():
    lint = _ci_jobs()["lint"]
    commands = _job_commands(lint)
    assert "--require-hashes -r requirements-ci.lock" in commands
    assert "bin/zizmor" in commands and "--persona auditor" in commands
    # zizmor is in the hashed CI lock and its input.
    assert re.search(r"^zizmor==[\d.]+$", (ROOT / "requirements-ci.in").read_text(), re.M)
    assert re.search(r"^zizmor==[\d.]+ \\$", (ROOT / "requirements-ci.lock").read_text(), re.M)
    # actionlint is a release binary verified against a pinned sha256.
    env = next(s for s in lint["steps"] if "ACTIONLINT_SHA256" in s.get("env", {}))["env"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", env["ACTIONLINT_VERSION"])
    assert re.fullmatch(r"[0-9a-f]{64}", env["ACTIONLINT_SHA256"])
    assert "sha256sum --check" in commands
    assert "/actionlint" in commands


def test_e2e_uploads_vulnerable_fixture_sarif_only_on_manual_runs():
    text = (WORKFLOWS / "action-e2e.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in _load(WORKFLOWS / "action-e2e.yml")[True]
    assert "github.event_name == 'push'" not in text
    assert text.count("github.event_name == 'workflow_dispatch' && 'true' || 'false'") == 2
    categories = re.findall(r"^\s+category: (\S+)$", text, re.M)
    assert categories and all(c.startswith("e2e-") for c in categories)


def test_dependabot_updates_use_a_cooldown():
    for update in _load(ROOT / ".github" / "dependabot.yml")["updates"]:
        assert update["cooldown"]["default-days"] >= 3, update["package-ecosystem"]


def test_codeowners_covers_the_mapping_registries():
    text = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    rules = [line.split() for line in text.splitlines() if line and not line.startswith("#")]
    owned = {pattern for pattern, *_ in rules}
    assert "/tf_eu_guard/mapping/" in owned
    for registry in (ROOT / "tf_eu_guard" / "mapping").glob("registry-*.yaml"):
        assert f"/tf_eu_guard/mapping/{registry.name}" in owned
    assert all(owners == ["@44aayush"] for _, *owners in rules)


def test_pull_request_and_issue_templates_exist():
    github = ROOT / ".github"
    pr = (github / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    for phrase in ("cites the specific article", "copy-pasteable", "real scan", "check_doc_counts"):
        assert phrase in pr
    for template in ("bug_report.yml", "mapping_request.yml"):
        form = _load(github / "ISSUE_TEMPLATE" / template)
        assert form["name"] and form["body"]


def test_gitignore_covers_generated_artifacts_and_keeps_local_tracking():
    lines = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert {".venv/", "uv.lock", "*.sarif", "sbom.json", "coverage.xml", "TASKS*.md"} <= lines


def test_obsolete_test_scripts_are_gone_and_unreferenced():
    for script in ("cleanup_legacy_files.sh", "run_all_tests.sh"):
        assert not (ROOT / "tests" / script).exists()
        assert script not in (ROOT / "tests" / "README.md").read_text(encoding="utf-8")
        assert script not in (ROOT / "README.md").read_text(encoding="utf-8")


# --- EUGUARD IDs expected by the workflows must be live, current checks ------

EUGUARD_ID = re.compile(r"\bEUGUARD_[A-Z0-9_]+\b")
EXPECTED_LOOP = re.compile(r"for\s+\w+\s+in\s+([^;\n]+?)\s*;\s*do")
CHECK_ID_DECL = re.compile(r"""(?:check_id\s*=\s*|\bid\s*=\s*)["'](EUGUARD_[A-Z0-9_]+)["']""")


def _workflow_expected_eu_ids() -> dict[str, set[str]]:
    """EUGUARD IDs the workflows expect, per workflow file.

    Covers every ``for <var> in ...; do`` list and any other EUGUARD ID that
    appears on a non-comment workflow line (jq selects, grep assertions).
    """
    found: dict[str, set[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        ids: set[str] = set()
        text = path.read_text(encoding="utf-8")
        for match in EXPECTED_LOOP.finditer(text):
            ids.update(EUGUARD_ID.findall(match.group(1)))
        for line in text.splitlines():
            if not line.lstrip().startswith("#"):
                ids.update(EUGUARD_ID.findall(line))
        if ids:
            found[path.name] = ids
    return found


def _registered_check_ids() -> set[str]:
    checks_dir = ROOT / "tf_eu_guard" / "checks"
    ids: set[str] = set()
    for path in checks_dir.rglob("*.py"):
        ids.update(CHECK_ID_DECL.findall(path.read_text(encoding="utf-8")))
    return ids


def _live_registry_ids() -> tuple[set[str], set[str]]:
    registry: set[str] = set()
    deprecated: set[str] = set()
    for path in sorted((ROOT / "tf_eu_guard" / "mapping").glob("registry-*.yaml")):
        for check_id, entry in (_load(path) or {}).items():
            if not str(check_id).startswith("EUGUARD_"):
                continue
            registry.add(check_id)
            if "DEPRECATED" in str(entry.get("risk", "")):
                deprecated.add(check_id)
    return registry, deprecated


def test_workflow_parser_finds_eu_ids():
    # Guard the guard: a broken regex must not make the check below vacuous.
    found = _workflow_expected_eu_ids()
    assert "action-e2e.yml" in found
    assert "EUGUARD_NIS2_001" in found["action-e2e.yml"]


def test_workflow_expected_eu_ids_are_current_registered_checks():
    registry, deprecated = _live_registry_ids()
    registered = _registered_check_ids()
    problems = []
    for name, ids in _workflow_expected_eu_ids().items():
        for check_id in sorted(ids):
            if check_id not in registry:
                problems.append(f"{name}: {check_id} is not in any registry")
            if check_id in deprecated:
                problems.append(f"{name}: {check_id} is a deprecated alias and is never emitted")
            if check_id not in registered:
                problems.append(
                    f"{name}: {check_id} is not registered by a check class "
                    "under tf_eu_guard/checks/"
                )
    assert not problems, "\n".join(problems)


def _final_dockerfile_stage() -> str:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    return re.split(r"^FROM\s", text, flags=re.MULTILINE)[-1]


def test_image_final_stage_has_oci_labels_linking_the_repository():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    repo_url = project["urls"]["Repository"]
    final = _final_dockerfile_stage()
    assert f'org.opencontainers.image.source="{repo_url}"' in final
    assert f'org.opencontainers.image.licenses="{project["license"]}"' in final
    assert 'org.opencontainers.image.title="tf-eu-guard"' in final
    match = re.search(r'org\.opencontainers\.image\.description="([^"]+)"', final)
    assert match and len(match.group(1)) <= 512


def test_image_build_step_sets_version_and_revision_labels():
    steps = _load(WORKFLOWS / "publish.yml")["jobs"]["image"]["steps"]
    build = next(s for s in steps if _is_build_push(s) and s["with"]["push"] is True)
    labels = build["with"]["labels"].splitlines()
    assert "org.opencontainers.image.version=${{ github.ref_name }}" in labels
    assert "org.opencontainers.image.revision=${{ github.sha }}" in labels


def test_image_version_label_default_matches_pyproject_version():
    """A version bump must not forget the Dockerfile's local-build default."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    final = _final_dockerfile_stage()
    match = re.search(r"^ARG VERSION=(\S+)$", final, flags=re.MULTILINE)
    assert match, "final stage must declare ARG VERSION=<default> after its FROM"
    assert match.group(1) == project["version"]
    assert 'org.opencontainers.image.version="${VERSION}"' in final


def test_image_scan_job_gates_on_fixable_high_and_critical():
    jobs = _ci_jobs()
    assert "image-scan" in jobs
    commands = _job_commands(jobs["image-scan"])
    for fragment in (
        "--ignore-unfixed",
        "--exit-code 1",
        "--severity HIGH,CRITICAL",
        "--ignorefile .trivyignore.yaml",
        "sha256sum --check",
    ):
        assert fragment in commands, fragment


def test_trivyignore_entries_have_statement_and_future_expiry():
    data = yaml.safe_load((ROOT / ".trivyignore.yaml").read_text(encoding="utf-8"))
    entries = data["vulnerabilities"]
    assert entries
    today = date.today()
    for entry in entries:
        assert str(entry.get("statement", "")).strip(), entry["id"]
        expiry = entry["expired_at"]
        assert isinstance(expiry, date), entry["id"]
        assert today < expiry <= today + timedelta(days=120), entry["id"]


def test_dockerfile_stages_share_one_pinned_base():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM\s+(\S+)", text, flags=re.MULTILINE)
    assert len(bases) == 2
    assert bases[0] == bases[1]
    assert re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", bases[0])


LOCALSTACK_IMAGE = (
    "localstack/localstack@sha256:59373b4a27dba3ec15c4db0b7455f0cb68c8a42300e2cbbe362b440f9a131697"
)


def test_emulator_job_is_pinned_read_only_and_runs_the_opt_in_tier():
    job = _ci_jobs()["emulator"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 20
    assert job["needs"] == ["lint"]
    assert "permissions" not in job  # inherits the read-only workflow default
    service = job["services"]["localstack"]
    assert service["image"] == LOCALSTACK_IMAGE
    assert service["ports"] == ["4566:4566"]
    assert service["env"] == {"SERVICES": "s3,sqs,dynamodb,sts,iam"}
    assert service["options"] == (
        '--health-cmd "curl -fs http://localhost:4566/_localstack/health"'
        " --health-interval 5s --health-timeout 5s --health-retries 20"
    )
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False
    terraform = next(
        s for s in job["steps"] if s.get("uses", "").startswith("hashicorp/setup-terraform@")
    )
    assert terraform["uses"].startswith(
        "hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e"
    )
    assert terraform["with"] == {"terraform_version": "1.17.2", "terraform_wrapper": False}
    commands = _job_commands(job)
    assert "pip install --require-hashes -r requirements.lock -r requirements-dev.lock" in commands
    assert "pip install --no-deps -e ." in commands
    run = next(s for s in job["steps"] if "pytest tests/emulator" in s.get("run", ""))
    assert 'pytest tests/emulator -p no:cacheprovider -o addopts=""' in run["run"]
    assert run["env"] == {"TFEG_RUN_EMULATOR": "1"}


def test_emulator_tier_skips_by_default():
    env = {k: v for k, v in os.environ.items() if k != "TFEG_RUN_EMULATOR"}
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/emulator", "-p", "no:cacheprovider"]
        + ["-o", "addopts=", "-q", "-rs"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert re.search(r"\b[1-9]\d* skipped\b", done.stdout), done.stdout
    assert not re.search(r"\b\d+ (passed|failed|error)", done.stdout), done.stdout


def test_emulator_override_is_not_inside_a_scanned_fixture():
    assert not list((ROOT / "tests" / "emulator" / "fixtures").rglob("*override*"))
    assert "access_key" not in "".join(
        p.read_text(encoding="utf-8")
        for p in (ROOT / "tests" / "emulator" / "fixtures").rglob("*.tf")
    )
