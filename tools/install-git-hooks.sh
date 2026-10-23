#!/usr/bin/env bash
# Enable the repository's tracked Git hooks for this checkout.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git config core.hooksPath .githooks
echo "Git hooks enabled: .githooks"
echo "The pre-commit hook will provision .venv with uv and run ruff, mypy, and pytest."
