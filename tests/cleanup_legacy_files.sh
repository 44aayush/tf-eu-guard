#!/usr/bin/env bash
# =============================================================================
# tf-eu-guard — remove superseded top-level test/scratch files
# =============================================================================
# These files were consolidated into tests/. This script removes an explicit
# allow-list only, handles tracked (git rm) vs untracked (rm) files, logs every
# action, and writes a record to tests/results/cleanup-<stamp>.txt for review.
#
# It intentionally does NOT touch:
#   * install_and_test.sh          (kept + updated as the environment bootstrap)
#   * tests/fixtures/checkov-vulnerable-tf.json (real scan data; runner fallback)
#
# Usage:  bash tests/cleanup_legacy_files.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || { echo "FATAL: cannot cd to repo root"; exit 1; }

RESULTS_DIR="$SCRIPT_DIR/results"; mkdir -p "$RESULTS_DIR"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
LOG="$RESULTS_DIR/cleanup-$STAMP.txt"
exec > >(tee "$LOG") 2>&1

echo "tf-eu-guard legacy cleanup — $STAMP"
echo "repo: $REPO_ROOT"
echo

# Superseded files -> their replacement under tests/
LEGACY=(
  "test_phase1.sh"                  # -> tests/run_all_tests.sh
  "quick_test.sh"                   # -> tests/run_all_tests.sh
  "MANUAL_TESTING_INSTRUCTIONS.md"  # -> tests/README.md
  "test_checkov_output.py"          # -> tests/test_checkov_runner.py + docs/checkov-schema.md
)

removed=0; absent=0
for f in "${LEGACY[@]}"; do
  if [ -e "$f" ]; then
    if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
      git rm -f -- "$f" && echo "git rm  $f" && removed=$((removed+1))
    else
      rm -f -- "$f" && echo "rm      $f  (untracked)" && removed=$((removed+1))
    fi
  else
    echo "skip    $f  (already absent)"; absent=$((absent+1))
  fi
done

echo
echo "removed: $removed   already-absent: $absent"
echo "log: $LOG"
