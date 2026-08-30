#!/usr/bin/env bash
# =============================================================================
# tf-eu-guard — install, test, and smoke-check in one pass
# =============================================================================
# Creates a virtualenv (if not already in one), installs the package with dev
# extras, runs the full test suite with coverage, and runs an end-to-end smoke
# scan against the bundled vulnerable example. Exits non-zero on any failure.
#
# Usage:            bash install_and_test.sh
# Override python:  PYTHON=python3.12 bash install_and_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python3}"
MIN_PY="3.10"

# --- Python version check -----------------------------------------------------
PY_VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$(printf '%s\n' "$MIN_PY" "$PY_VER" | sort -V | head -n1)" != "$MIN_PY" ]; then
  echo "Error: Python $MIN_PY+ required, found $PY_VER"
  exit 1
fi
echo "Using Python $PY_VER"

# --- venv ----------------------------------------------------------------------
if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "Creating virtual environment..."
  $PYTHON -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "Installing tf-eu-guard..."
python -m pip install --upgrade pip --quiet
python -m pip install -e ".[dev]"

echo "Running tests..."
pytest --cov=tf_eu_guard --cov-report=term-missing -q

echo "Running smoke test (scan examples/vulnerable-aws/)..."
tf-eu-guard scan examples/vulnerable-aws/ --output json > /dev/null

echo "All checks passed."
