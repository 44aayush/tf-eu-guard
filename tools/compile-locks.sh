#!/usr/bin/env bash
# Regenerate every hashed lock file. CI runs this same script and fails when
# `git diff` is not empty, so the committed locks cannot drift from their inputs.
#
#   requirements.lock      runtime dependencies from pyproject.toml. Universal
#                          (platform markers), resolved from Python 3.11.5, so
#                          one file serves the CI matrix (3.11-3.14; Linux, macOS,
#                          Windows) and the Docker image (Python 3.12). 3.11.5 is
#                          the floor because soupsieve 4 needs it; resolving from
#                          3.11.0 would also pin a vulnerable soupsieve 2.x.
#   requirements-dev.lock  test and lint tools, constrained by requirements.lock.
#   requirements-ci.lock   build and supply-chain tooling, resolved for the
#                          Docker/CI Python (3.12).
#
# uv keeps the versions already recorded in an existing lock, so a run only
# changes pins when an input changed. Pass --upgrade to move them.
# Requires uv; the pinned version is in requirements-ci.lock.
set -euo pipefail
cd "$(dirname "$0")/.."

# The header uv writes into each lock names this command; spelling out the
# options keeps the Python version visible there (tests/test_ci_workflows.py
# compares it with the Dockerfile).
compile_lock() {
  local python_version="$1" output="$2" input="$3"
  shift 3
  UV_CUSTOM_COMPILE_COMMAND="tools/compile-locks.sh (uv pip compile --universal --python-version ${python_version} ${input} -> ${output})" \
    uv pip compile --universal --generate-hashes --no-emit-index-url --strip-extras --quiet \
    --python-version "${python_version}" --output-file "${output}" "${input}" "$@"
}

extra=("$@")
compile_lock 3.11.5 requirements.lock pyproject.toml "${extra[@]}"
compile_lock 3.11.5 requirements-dev.lock requirements-dev.in "${extra[@]}"
compile_lock 3.12 requirements-ci.lock requirements-ci.in --allow-unsafe "${extra[@]}"
