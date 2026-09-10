#!/usr/bin/env bash
# =============================================================================
# tf-eu-guard — consolidated manual + integration test runner
# =============================================================================
# Runs the whole verification suite end-to-end and writes a full transcript to
# tests/results/ so it can be reviewed offline (the authoring environment can
# neither run Checkov nor delete files).
#
# Design notes:
#   * NO `set -e` — every test runs even if an earlier one fails; a
#     PASS / FAIL / SKIP / WARN summary is printed at the end.
#   * Checkov-dependent tests SKIP (not FAIL) when Checkov is absent from the
#     Python environment (invoked as `python -m checkov`, not a PATH binary).
#   * The security/auditor reports (and --output all) are generated into
#     tests/results/ and asserted to be real HTML documents (Phase 4 — no stubs).
#   * Checkov is run ONCE; the raw JSON is cached at tests/results/scan.json and
#     reused by the enrichment test (and left there for review).
#
# Usage:
#   bash tests/run_all_tests.sh                    # scans ./vulnerable_tf
#   TF_TARGET=path/to/tf bash tests/run_all_tests.sh
#
# Exit code: 0 when nothing FAILED; 1 otherwise (SKIP/WARN do not fail the run).
# =============================================================================

# ---- locate repo root (this script lives in tests/) ------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || { echo "FATAL: cannot cd to repo root"; exit 1; }

# ---- transcript ------------------------------------------------------------
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
LATEST="$RESULTS_DIR/latest-run.txt"
ARCHIVE="$RESULTS_DIR/run-$STAMP.txt"
# Mirror all stdout + stderr to the console AND both transcript files.
exec > >(tee "$LATEST" "$ARCHIVE") 2>&1

# ---- config ----------------------------------------------------------------
TF_TARGET="${TF_TARGET:-examples}"
SCAN_JSON="$RESULTS_DIR/scan.json"
# The registry was split into per-cloud files (registry-aws.yaml, …) — pass the
# mapping directory so load_registry merges every registry-*.yaml found there.
REG="tf_eu_guard/mapping"

# ---- environment: venv + interpreter + checkov -----------------------------
if [ -f "venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source venv/bin/activate && echo "[env] activated venv/"
elif [ -f ".venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate && echo "[env] activated .venv/"
else
  echo "[env] no venv found — using system python (run ./install_and_test.sh first)"
fi

PY="python"
command -v python >/dev/null 2>&1 || PY="python3"
command -v "$PY" >/dev/null 2>&1 || { echo "FATAL: no python interpreter found"; exit 1; }

# Checkov is invoked as `python -m checkov` (see checkov_runner.py), so detect
# it in this Python environment — not via a PATH-resolved CLI binary, which a
# stray global install could satisfy while the venv actually lacks Checkov.
HAVE_CHECKOV=0
$PY -c "import checkov" >/dev/null 2>&1 && HAVE_CHECKOV=1

# ---- counters + helpers ----------------------------------------------------
PASS=0; FAIL=0; SKIP=0; WARN=0
declare -a FAILED_NAMES=()

hr(){ printf '%s\n' "-------------------------------------------------------------"; }
section(){
  echo; echo "============================================================="
  echo "  $*"
  echo "============================================================="
}

# run_test <name> <function>  — function return: 0 PASS / 2 SKIP / 3 WARN / else FAIL
run_test(){
  local name="$1" fn="$2" rc=0
  hr; echo ">> TEST: $name"
  "$fn"; rc=$?
  case "$rc" in
    0) echo "   PASS: $name"; PASS=$((PASS+1)) ;;
    2) echo "   SKIP: $name"; SKIP=$((SKIP+1)) ;;
    3) echo "   WARN: $name (known limitation)"; WARN=$((WARN+1)) ;;
    *) echo "   FAIL: $name (rc=$rc)"; FAIL=$((FAIL+1)); FAILED_NAMES+=("$name") ;;
  esac
}

# =============================================================================
# Tests
# =============================================================================

# --- 0. environment snapshot (informational; PASS if the package imports) ---
t_env(){
  echo "repo root : $REPO_ROOT"
  echo "tf target : $TF_TARGET"
  echo "python    : $($PY --version 2>&1)  ($(command -v $PY))"
  if [ "$HAVE_CHECKOV" -eq 1 ]; then
    echo "checkov   : $($PY -m checkov.main --version 2>&1 | head -1)"
  else
    echo "checkov   : NOT INSTALLED in this Python environment (checkov-dependent tests will SKIP)"
  fi
  $PY -c "import tf_eu_guard; print('tf_eu_guard :', tf_eu_guard.__version__)" || return 1
  $PY -c "import yaml" 2>/dev/null && echo "pyyaml    : OK" \
    || { echo "pyyaml    : MISSING — run: pip install -e .[dev]"; return 1; }
  return 0
}

# --- 1. CLI version ----------------------------------------------------------
t_cli_version(){
  local out
  out="$($PY -m tf_eu_guard.cli version 2>&1)"; echo "$out"
  echo "$out" | grep -q "tf-eu-guard version" || return 1
}

# --- 2. PHASE 2: registry structural validation -----------------------------
t_registry(){
  TFEG_REG="$REG" $PY - <<'PY'
import os, re, sys
from pathlib import Path
from tf_eu_guard.mapping.loader import load_registry
from tf_eu_guard.models import Framework, Severity

reg = load_registry(Path(os.environ["TFEG_REG"]))
n = len(reg)
print(f"loaded {n} mappings")
ok = True
if n < 20:
    print(f"  ! expected >= 20 mappings, got {n}"); ok = False

art = re.compile(r"^Art\. \d+(\(\d+\))?(\([a-z]\))?$")
by_fw, sev = {}, {}
for cid, m in sorted(reg.items()):
    sev[m.severity.value] = sev.get(m.severity.value, 0) + 1
    if not (m.check_name.strip() and m.risk_explanation.strip() and m.remediation.strip()):
        print(f"  ! {cid}: empty check_name/risk/remediation"); ok = False
    if not isinstance(m.severity, Severity):
        print(f"  ! {cid}: bad severity"); ok = False
    for a in m.articles:
        by_fw[a.framework.value] = by_fw.get(a.framework.value, 0) + 1
        if not art.match(a.article):
            print(f"  ! {cid}: malformed article {a.article!r}"); ok = False

def nis2(cid): return {a.article for a in reg[cid].articles if a.framework is Framework.NIS2}
def gdpr(cid): return {a.article for a in reg[cid].articles if a.framework is Framework.GDPR}
for cid in ("CKV_AWS_273", "CKV_AWS_287"):        # access control -> 21(2)(i)
    if cid in reg and ("Art. 21(2)(i)" not in nis2(cid) or "Art. 21(2)(e)" in nis2(cid)):
        print(f"  ! {cid}: access control must be NIS2 21(2)(i), not (e)"); ok = False
for cid in ("CKV_AWS_16", "CKV_AWS_145"):         # encryption -> 21(2)(h)/32(1)(a)
    if cid in reg and ("Art. 21(2)(h)" not in nis2(cid) or "Art. 32(1)(a)" not in gdpr(cid)):
        print(f"  ! {cid}: encryption must be NIS2 21(2)(h) + GDPR 32(1)(a)"); ok = False

print("  severity          :", dict(sorted(sev.items())))
print("  article refs / fw :", dict(sorted(by_fw.items())))
print("  check IDs         :", ", ".join(sorted(reg)))
sys.exit(0 if ok else 1)
PY
}

# --- 3. Checkov runner: scan once, cache scan.json --------------------------
t_checkov_scan(){
  if [ "$HAVE_CHECKOV" -ne 1 ]; then
    echo "checkov not installed — skipping live scan"
    if [ -f "tests/fixtures/checkov-vulnerable-tf.json" ]; then
      cp "tests/fixtures/checkov-vulnerable-tf.json" "$SCAN_JSON"
      echo "fallback: copied tests/fixtures/checkov-vulnerable-tf.json -> $SCAN_JSON (enrichment can still run)"
    fi
    return 2
  fi
  if [ ! -d "$TF_TARGET" ]; then echo "TF target '$TF_TARGET' not found"; return 1; fi
  TFEG_TARGET="$TF_TARGET" TFEG_OUT="$SCAN_JSON" $PY - <<'PY'
import json, os, sys
from pathlib import Path
from tf_eu_guard.checkov_runner import run_checkov, extract_failed_checks
data = run_checkov(Path(os.environ["TFEG_TARGET"]))
Path(os.environ["TFEG_OUT"]).write_text(json.dumps(data, indent=2))
findings = extract_failed_checks(data)
ids = sorted({c["check_id"] for c in findings})
print(f"failed checks: {len(findings)}   unique IDs: {len(ids)}")
print("unique:", ", ".join(ids))
sys.exit(0 if findings else 1)
PY
}

# --- 4. PHASE 2: enrichment (join scan -> registry) -------------------------
t_enrichment(){
  if [ ! -f "$SCAN_JSON" ]; then echo "no scan.json (checkov skipped) — skipping"; return 2; fi
  TFEG_SCAN="$SCAN_JSON" TFEG_REG="$REG" $PY - <<'PY'
import json, os, sys
from pathlib import Path
from tf_eu_guard.checkov_runner import extract_failed_checks
from tf_eu_guard.mapping.loader import load_registry, enrich_findings
data = json.loads(Path(os.environ["TFEG_SCAN"]).read_text())
reg = load_registry(Path(os.environ["TFEG_REG"]))
findings = extract_failed_checks(data)
enriched = enrich_findings(findings, reg)
fired = sorted({e.check_id for e in enriched})
scanned_ids = {c["check_id"] for c in findings}
dormant = sorted(set(reg) - scanned_ids)
unmapped = sorted(scanned_ids - set(reg))
print(f"checkov findings : {len(findings)}")
print(f"enriched rows    : {len(enriched)}   unique mapped IDs: {len(fired)}")
print("fired   :", ", ".join(fired))
print("dormant (in registry, not in this scan):", ", ".join(dormant) or "none")
print(f"unmapped (in scan, no registry entry): {len(unmapped)}", ", ".join(unmapped) or "none")
print("  -> excluded from the mapped report; the CLI surfaces this count as 'present-but-unmapped'")
ok = bool(enriched) and all(e.check_id in reg and e.articles for e in enriched)
sys.exit(0 if ok else 1)
PY
}

# --- 4b. PHASE 3: custom checks fire alongside stock checks, and enrich ------
# Fulfils PROJECT_PLAN.md §3.3: a live scan must surface custom EUGUARD_*
# findings AND stock CKV_AWS_* findings together, with the custom findings
# enriched via the registry. Needs a live scan (the cached fallback JSON
# predates the custom checks), so it SKIPs when checkov is absent.
t_phase3_custom(){
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping (needs a live scan)"; return 2; }
  if [ ! -f "$SCAN_JSON" ]; then echo "no scan.json — skipping"; return 2; fi
  TFEG_SCAN="$SCAN_JSON" TFEG_REG="$REG" $PY - <<'PY'
import json, os, sys
from pathlib import Path
from tf_eu_guard.checkov_runner import extract_failed_checks
from tf_eu_guard.mapping.loader import load_registry, enrich_findings
data = json.loads(Path(os.environ["TFEG_SCAN"]).read_text())
reg = load_registry(Path(os.environ["TFEG_REG"]))
findings = extract_failed_checks(data)
ids = {c["check_id"] for c in findings if c["check_id"]}
custom = sorted(i for i in ids if i.startswith("EUGUARD_"))
stock  = sorted(i for i in ids if i.startswith("CKV"))
enriched = enrich_findings(findings, reg)
enriched_custom = sorted({e.check_id for e in enriched if e.check_id.startswith("EUGUARD_")})
print("custom (EUGUARD_*) fired :", ", ".join(custom) or "NONE")
print(f"stock  (CKV*) fired      : {len(stock)} unique")
print("custom findings enriched :", ", ".join(enriched_custom) or "NONE")
if not custom:
    print("  ! no EUGUARD_* findings — is --external-checks-dir wired into run_checkov,")
    print("    and does each checks/ subdir carry an __init__.py?")
# Require at least one custom check to fire AND enrich, with stock checks still present.
ok = bool(custom) and bool(stock) and bool(enriched_custom)
sys.exit(0 if ok else 1)
PY
}

# --- 5. dev report (real CLI end-to-end) ------------------------------------
t_report_dev(){
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping"; return 2; }
  $PY -m tf_eu_guard.cli scan "$TF_TARGET" --output dev || return 1
}

# --- 6. json report + shape check -------------------------------------------
t_report_json(){
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping"; return 2; }
  local jf="$RESULTS_DIR/report.json"
  $PY -m tf_eu_guard.cli scan "$TF_TARGET" --output json > "$jf" 2>/dev/null
  TFEG_JSON="$jf" $PY - <<'PY'
import json, os
data = json.load(open(os.environ["TFEG_JSON"]))
assert isinstance(data, list), "json output is not a list"
print(f"json findings: {len(data)}")
for f in data[:3]:
    assert {"check_id", "severity", "articles"} <= set(f), f"missing keys in {f.get('check_id')}"
print("shape OK; sample IDs:", [f["check_id"] for f in data[:5]])
PY
}

# --- 7. framework filters (nis2 / gdpr) -------------------------------------
t_framework_filters(){
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping"; return 2; }
  local rc=0
  for fw in nis2 gdpr; do
    echo "-- framework: $fw --"
    TFEG_FW="$fw" TF_TARGET="$TF_TARGET" $PY - <<'PY' || rc=1
import json, os, subprocess, sys
fw = os.environ["TFEG_FW"]; target = os.environ.get("TF_TARGET", "examples")
want = {"nis2": "NIS2", "gdpr": "GDPR"}[fw]
p = subprocess.run(
    [sys.executable, "-m", "tf_eu_guard.cli", "scan", target, "--output", "json", "--framework", fw],
    capture_output=True, text=True,
)
data = json.loads(p.stdout or "[]")
bad = [f["check_id"] for f in data if want not in [a["framework"] for a in f["articles"]]]
print(f"  {fw}: {len(data)} findings; every finding cites {want}: {not bad}")
sys.exit(1 if bad else 0)
PY
  done
  return $rc
}

# --- 8. security / auditor HTML reports (Phase 4) --------------------------
# Generate each HTML report into tests/results/ and assert it is a real,
# non-empty HTML document that actually rendered enriched findings.
_report_html(){   # $1 = security|auditor ; $2 = output basename
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping"; return 2; }
  local fmt="$1" out="$RESULTS_DIR/$2"
  rm -f "$out"
  $PY -m tf_eu_guard.cli scan "$TF_TARGET" --output "$fmt" --output-file "$out" || return 1
  [ -s "$out" ] || { echo "expected HTML report was not written: $out"; return 1; }
  head -1 "$out" | grep -qi '<!DOCTYPE html>' || { echo "report does not start with <!DOCTYPE html>"; return 1; }
  grep -qi '</html>' "$out" || { echo "report HTML is not closed"; return 1; }
  grep -Eq 'EUGUARD_|CKV_AWS_' "$out" || { echo "no enriched findings rendered in report"; return 1; }
  echo "wrote $fmt report: $out ($(wc -c < "$out" | tr -d ' ') bytes)"
}
t_report_security(){ _report_html security scan-report.html; }
t_report_auditor(){  _report_html auditor  auditor-report.html; }

# --- 8b. --output all: dev + security + auditor HTML in one run --------------
# Writes all three HTML files into tests/results/ via --output-dir and asserts
# each is a real, non-empty HTML document.
t_report_all(){
  [ "$HAVE_CHECKOV" -eq 1 ] || { echo "checkov not installed — skipping"; return 2; }
  local d="$RESULTS_DIR"
  # The CLI writes timestamped names (dev_report_DDMMYYYYHHMM.html) so runs
  # don't overwrite each other — clear this run's candidates before scanning.
  rm -f "$d"/dev_report_*.html "$d"/scan_report_*.html "$d"/auditor_report_*.html
  $PY -m tf_eu_guard.cli scan "$TF_TARGET" --output all --output-dir "$d" || return 1
  local prefix f
  for prefix in dev_report scan_report auditor_report; do
    f=$(ls -t "$d/${prefix}"_*.html 2>/dev/null | head -1)
    { [ -n "$f" ] && [ -s "$f" ]; } || { echo "expected report was not written: $d/${prefix}_<ts>.html"; return 1; }
    head -1 "$f" | grep -qi '<!DOCTYPE html>' || { echo "$f does not start with <!DOCTYPE html>"; return 1; }
    grep -qi '</html>' "$f" || { echo "$f HTML is not closed"; return 1; }
    grep -Eq 'EUGUARD_|CKV_AWS_' "$f" || { echo "$f rendered no enriched findings"; return 1; }
  done
  echo "wrote all 3 HTML reports into $d/ (dev_report, scan_report, auditor_report — timestamped)"
}

# --- 9. pytest unit suite (hermetic; live smoke enabled when checkov present) -
t_pytest(){
  $PY -c "import pytest" 2>/dev/null \
    || { echo "pytest not installed — skipping (pip install -e .[dev])"; return 2; }
  local flag=""; [ "$HAVE_CHECKOV" -eq 1 ] && flag="1"
  # -o addopts="-q" neutralises the --cov addopts so this runs without pytest-cov.
  TFEG_RUN_CHECKOV="$flag" $PY -m pytest tests -o addopts="-q" || return 1
}

# =============================================================================
# Run
# =============================================================================
section "tf-eu-guard test run — $STAMP"
run_test "environment"             t_env
run_test "cli:version"             t_cli_version
run_test "phase2:registry"         t_registry
run_test "checkov:scan"            t_checkov_scan
run_test "phase2:enrichment"       t_enrichment
run_test "phase3:custom-checks"    t_phase3_custom
run_test "report:dev"              t_report_dev
run_test "report:json"             t_report_json
run_test "framework:filters"       t_framework_filters
run_test "report:security"         t_report_security
run_test "report:auditor"          t_report_auditor
run_test "report:all"              t_report_all
run_test "pytest:unit-suite"       t_pytest

# ---- legacy-file check (non-destructive) -----------------------------------
section "legacy file check"
legacy=(test_phase1.sh quick_test.sh MANUAL_TESTING_INSTRUCTIONS.md test_checkov_output.py)
present=()
for f in "${legacy[@]}"; do [ -e "$f" ] && present+=("$f"); done
if [ "${#present[@]}" -gt 0 ]; then
  echo "superseded files still present (consolidated into tests/):"
  printf '   - %s\n' "${present[@]}"
  echo "remove them with:  bash tests/cleanup_legacy_files.sh"
else
  echo "clean — no superseded root files present."
fi

# ---- summary ---------------------------------------------------------------
section "SUMMARY"
echo "PASS: $PASS   FAIL: $FAIL   SKIP: $SKIP   WARN(known-stub): $WARN"
if [ "$FAIL" -gt 0 ]; then
  echo "failed:"; printf '   - %s\n' "${FAILED_NAMES[@]}"
fi
echo
echo "transcript : $LATEST"
echo "archive    : $ARCHIVE"
echo "raw scan   : $SCAN_JSON"
echo

[ "$FAIL" -eq 0 ]
