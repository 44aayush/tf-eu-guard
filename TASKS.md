# TASKS.md — tf-eu-guard-omni Improvement Roadmap

> **Status:** Alpha → v1.0 Production Readiness  
> **Last updated:** 2026-08-30  
> **Priority:** P0 = Blocker | P1 = Required for v1.0 | P2 = Adoption enabler | P3 = Nice-to-have

---

## P0 — Critical Fixes (Do First)

### Task 1: Fix Python Version Floor & Publish to PyPI

**Problem:** `pyproject.toml` pins `requires-python = ">=3.14.4"`, which blocks installation on Python 3.12 (Ubuntu 24.04 default) and most CI runners. Verified: the tool runs perfectly on 3.12 — the pin is arbitrary.

**Steps:**
1. **Lower the floor:** Change `requires-python = ">=3.10"` (or `>=3.11` if you genuinely need 3.11+ features). Test on 3.10, 3.11, 3.12, 3.13 in CI.
2. **Add a matrix CI job:** Update `.github/workflows/ci.yml` to test across `[3.10, 3.11, 3.12, 3.13]`.
---

### Task 2: Add Severity-Based Exit Codes for CI/CD Gating

**Problem:** `tf-eu-guard scan` returns exit code `0` even with CRITICAL findings. This makes it unusable as a CI gate.

**Steps:**
1. Add CLI flags: `--fail-on-severity {CRITICAL,HIGH,MEDIUM,LOW}` and `--fail-on-any` (default: disabled for backward compatibility, or enabled for CI).
2. In `cli.py`, after `generate_report()`, count findings at or above the threshold severity.
3. If count > 0, `sys.exit(1)` instead of `sys.exit(0)`.
4. Add tests in `tests/test_cli.py` asserting exit codes for each severity level.
5. Update README Usage section to show the CI pattern:
   ```bash
   tf-eu-guard scan ./terraform --fail-on-severity HIGH
   ```

---

### Task 3: Remove CRA & DORA From Scope / Future Roadmap

**Problem:** The README lists CRA and DORA as "future scope," but:
- **CRA** is a product-security/SDLC regulation, not an infrastructure misconfiguration concern. A static IaC linter has no natural path to CRA coverage.
- **DORA** is already live (in force since Jan 2025, Register-of-Information deadline passed March 2026). Listing it as "future work" implies it isn't live yet, which is misleading.

**Steps:**
1. **In README:**
   - Remove CRA and DORA from the "Idea" / concept description.
   - In the Scope table, change CRA from "❌ Out of scope" to simply **not listed at all** (or add a one-line footnote: "CRA and DORA are out of scope for this tool as they address product lifecycle and financial-sector operational resilience, not cloud infrastructure configuration.").
   - Remove "DORA mappings: Financial sector compliance (future scope)" from Contributing section.
2. **In `registry.yaml` and docs:** Remove any DORA placeholder comments or TODOs.
3. **In `PROJECT_PLAN.md`:** Remove DORA/CRA roadmap items (or delete the whole file per Task 13).

---

### Task 4: Sync Claude Code Skill Documentation

**Problem:** `.claude/skills/tf-eu-guard/SKILL.md` incorrectly states that `security` and `auditor` output formats "are not implemented yet." They are implemented. This causes Claude to avoid generating the best report format.

**Steps:**
1. Open `.claude/skills/tf-eu-guard/SKILL.md`.
2. Update the description to reflect all working formats: `dev`, `security`, `auditor`, `json`, `all`.
3. Update example prompts to recommend `--output auditor` for compliance review and `--output all` for full coverage.
4. Verify by running `/tf-eu-guard` in Claude Code and checking it suggests the correct formats.

---

## P1 — Production Readiness

### Task 5: Restructure README — Remove Redundant Sections

**Remove the following sections entirely:**

| Section | Reason |
|---------|--------|
| **Built With** | Redundant; Acknowledgments already covers Checkov, terragoat, and legal sources. |
| **Terminal Recording** | Adds visual bloat; screenshots and HTML report links are sufficient. |
| **Before & After** | The enriched output example is already shown in "What This Does" / Quick Start. The side-by-side table is redundant. |
| **Examples** | The `examples/vulnerable-aws/` and `examples/compliant-aws/` references should move to a single "Try it out" line in Quick Start, not a full section. The `vulnerable_tf/end2end/` reference should move to Testing docs. |

**Steps:**
1. Delete the four section headings and their content from `README.md`.
2. Move the `examples/vulnerable-aws/` and `examples/compliant-aws/` one-liners into Quick Start as:
   ```markdown
   > **Try it:** Run `tf-eu-guard scan examples/vulnerable-aws/ --output all` to see ~30 mapped findings,
   > or `tf-eu-guard scan examples/compliant-aws/ --output dev` to see a clean scan.
   ```
3. Move `vulnerable_tf/end2end/` reference to `CONTRIBUTING.md` or `tests/README.md`.

---

### Task 6: Rewrite "Report Formats" → "Usage" with Commands & Screenshots

**Problem:** The current "Report Formats" section is reference-heavy and lacks visual proof for new users.

**Steps:**
1. **Rename section** from `## Report Formats` to `## Usage`.
2. **Restructure as command-per-subsection** with a one-line explanation and a screenshot path:

   ```markdown
   ## Usage

   ### Developer Scan
   Quick terminal output for engineers fixing issues:
   ```bash
   tf-eu-guard scan ./terraform --output dev
   ```
   ![Dev report terminal output](docs/screenshots/dev-terminal.png)

   ### Security Dashboard
   HTML report with severity breakdown and compliance tags:
   ```bash
   tf-eu-guard scan ./terraform --output security
   ```
   ![Security dashboard](docs/screenshots/scan-report.png)

   ### Auditor Compliance Matrix
   Article-by-article view for audit preparation:
   ```bash
   tf-eu-guard scan ./terraform --output auditor
   ```
   ![Auditor report](docs/screenshots/auditor-report.png)

   ### JSON (CI/CD & Tooling)
   Machine-readable output for pipelines:
   ```bash
   tf-eu-guard scan ./terraform --output json --framework nis2
   ```

   ### Generate All Reports at Once
   ```bash
   tf-eu-guard scan ./terraform --output all
   ```
   ```
3. **Generate real screenshots:** Run the tool against `examples/vulnerable-aws/`, open each HTML report, take clean screenshots, save to `docs/screenshots/`, and commit them. Ensure no sensitive data is in the screenshots.
4. **Remove the "Tools" subsection** (if it exists listing dependencies like `rich`, `jinja2`) — users don't need to know the internal library stack.

---

### Task 7: Optimize `install_and_test.sh`

**Problem:** The install script likely does redundant work, lacks error handling, or pins versions too aggressively.

**Steps:**
1. **Review the current script.** Ensure it:
   - Checks Python version (≥3.10, not 3.14.4).
   - Creates a virtual environment if not in one.
   - Installs in editable mode: `pip install -e ".[dev]"`.
   - Runs the full test suite: `pytest --cov=tf_eu_guard --cov-report=term-missing`.
   - Runs the end-to-end smoke test against `examples/vulnerable-aws/`.
   - Returns non-zero on any failure.
2. **Simplify to a single, robust script:**
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail

   PYTHON="${PYTHON:-python3}"
   MIN_PY="3.10"

   # Check Python version
   PY_VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
   if [ "$(printf '%s\n' "$MIN_PY" "$PY_VER" | sort -V | head -n1)" != "$MIN_PY" ]; then
       echo "Error: Python $MIN_PY+ required, found $PY_VER"
       exit 1
   fi

   # Setup venv if needed
   if [ -z "${VIRTUAL_ENV:-}" ]; then
       echo "Creating virtual environment..."
       $PYTHON -m venv .venv
       source .venv/bin/activate
   fi

   echo "Installing tf-eu-guard..."
   pip install -e ".[dev]"

   echo "Running tests..."
   pytest --cov=tf_eu_guard --cov-report=term-missing -q

   echo "Running smoke test..."
   tf-eu-guard scan examples/vulnerable-aws/ --output json > /dev/null

   echo "All checks passed."
   ```
3. Make it executable: `chmod +x install_and_test.sh`.
4. Update CI to call this script instead of inline steps, ensuring CI and local dev use the same path.

---

### Task 8: Partition the Compliance Registry

**Problem:** `registry.yaml` is one flat 104KB file. At 116 entries it's manageable, but adding Azure, GCP, and community contributions will create merge conflicts and review bottlenecks. No schema validation exists for entries.

**Steps:**
1. **Split by provider and framework:**
   ```
   tf_eu_guard/mapping/
   ├── __init__.py
   ├── schema.yaml          # JSON-schema or YAML-schema for validation
   ├── loader.py            # Updated to glob-load all registry-*.yaml files
   ├── registry-aws.yaml    # Current AWS mappings
   ├── registry-azure.yaml  # (placeholder for future)
   └── registry-gcp.yaml    # (placeholder for future)
   ```
2. **Add schema validation in CI:**
   - Define a schema (e.g., using `pydantic` or `jsonschema`) that enforces required fields: `check_id`, `check_name`, `articles` (list with `framework`, `article`, `title`), `risk`, `remediation`, `severity` (enum: LOW/MEDIUM/HIGH/CRITICAL).
   - Add a CI step: `python -c "from tf_eu_guard.mapping.loader import validate_all; validate_all()"` that validates every registry file against the schema.
3. **Update `loader.py`** to glob all `registry-*.yaml` files in the mapping directory and merge them at runtime.
4. **Update tests** to assert schema compliance on all registry files.

---

### Task 9: Add CLI/Terminal-Report Test Coverage

**Problem:** Test coverage is 66% overall, but the CLI entry point and terminal report generator are at 0%. The core enrichment engine is near 100%, which is good, but the user-facing surface is untested.

**Steps:**
1. Add `tests/test_cli.py` covering:
   - `scan` command with each `--output` format
   - `--framework nis2` and `--framework gdpr` filtering
   - `--checkov-json` passthrough mode
   - Invalid paths and error handling
   - Exit codes (once Task 2 is done)
2. Add `tests/test_reporting_terminal.py` covering:
   - `generate_dev_report()` with mock findings
   - Severity sorting
   - Empty findings handling
3. Target: bring overall coverage to ≥80%, with CLI at ≥70%.

---

## P2 — Distribution & Adoption

### Task 10: Create GitHub Action

**Problem:** No one-line CI integration exists. A GitHub Action is the primary adoption path for security tools.

**Steps:**
1. Create `action.yml` in repo root:
   ```yaml
   name: 'tf-eu-guard'
   description: 'EU compliance security linter for Terraform (NIS2 + GDPR)'
   inputs:
     path:
       description: 'Path to Terraform directory'
       required: true
       default: './terraform'
     output:
       description: 'Report format (dev, security, auditor, json, all)'
       required: false
       default: 'json'
     framework:
       description: 'Framework filter (nis2, gdpr, all)'
       required: false
       default: 'all'
     fail-on-severity:
       description: 'Fail the build if findings at or above this severity exist'
       required: false
       default: 'HIGH'
   runs:
     using: 'docker'
     image: 'Dockerfile'
     args:
       - ${{ inputs.path }}
       - --output
       - ${{ inputs.output }}
       - --framework
       - ${{ inputs.framework }}
       - --fail-on-severity
       - ${{ inputs.fail-on-severity }}
   ```
2. Create a `Dockerfile` for the action:
   ```dockerfile
   FROM python:3.12-slim
   RUN pip install tf-eu-guard==0.1.0
   ENTRYPOINT ["tf-eu-guard", "scan"]
   ```
3. Publish the action to the GitHub Marketplace (requires a release).
4. Add a usage example to README:
   ```yaml
   - uses: 44aayush/tf-eu-guard-omni@v1
     with:
       path: './infra'
       fail-on-severity: 'HIGH'
   ```

---

### Task 11: Add Pre-commit Hook

**Steps:**
1. Create `.pre-commit-hooks.yaml` in repo root:
   ```yaml
   - id: tf-eu-guard
     name: tf-eu-guard EU Compliance Check
     entry: tf-eu-guard scan
     language: python
     files: \.tf$
     args: ['--output', 'dev', '--fail-on-severity', 'HIGH']
   ```
2. Document usage in README:
   ```yaml
   repos:
     - repo: https://github.com/44aayush/tf-eu-guard-omni
       rev: v0.1.0
       hooks:
         - id: tf-eu-guard
   ```

---

### Task 12: Validate All "Unverified" Checkov IDs in Registry

**Problem:** Several registry entries (noted in comments) were authored from the Checkov 3.3.13 policy index but not confirmed against an actual scan. Mispredicted IDs will cause silent misses (findings not enriched) or errors.

**Steps:**
1. Run `checkov -d examples/vulnerable-aws/ --framework terraform --quiet` and capture all check IDs that fire.
2. Run `checkov -d vulnerable_tf/end2end/ --framework terraform --quiet` and capture all check IDs.
3. Cross-reference every ID in `registry.yaml` against the actual scan output.
4. For any ID that never fires, verify it exists in Checkov 3.3.13's policy index. If it doesn't exist or was renamed, update or remove the mapping.
5. Add a CI regression test that asserts: "Every check ID in the registry exists in Checkov's current policy index." This can be done by running `checkov --list` and diffing.

---

## P3 — Cleanup & Polish

### Task 13: Remove `PROJECT_PLAN.md`

**Problem:** The project plan frames the tool as "4-6 weeks, portfolio/thesis scope." This undermines production credibility. It should not be in the repo once you pitch this as a real open-source tool.

**Steps:**
1. Delete `PROJECT_PLAN.md`.
2. If it contains useful technical decisions, migrate them to `docs/ARCHITECTURE.md` or `docs/DECISIONS.md` with the portfolio framing removed.
3. Ensure no README links point to `PROJECT_PLAN.md`.

---

### Task 14: Add CONTRIBUTING.md with Registry Contribution Guidelines

**Problem:** The README invites contributions but the single-file registry isn't ready for community PRs without guidelines.

**Steps:**
1. Create `CONTRIBUTING.md` covering:
   - How to propose a new mapping (issue first, then PR)
   - Schema requirements (see Task 8)
   - How to verify a Checkov ID against a real scan
   - Required fields: risk explanation must cite specific legal text, remediation must be copy-paste Terraform code
   - Test requirements: add a fixture in `examples/` that triggers the new check, assert it appears in output
2. Add a `good first issue` label for registry expansion tasks.

---

### Task 15: Add Azure & GCP Seed Mappings

**Problem:** The README claims the tool scans "AWS, Azure, GCP" but the registry is AWS-only. This is misleading.

**Steps:**
1. Add 10-20 high-value Azure mappings (e.g., unencrypted Storage Account, public SQL Server, missing NSG flow logs) to `registry-azure.yaml`.
2. Add 10-20 high-value GCP mappings (e.g., unencrypted GCS bucket, public Cloud SQL, missing VPC flow logs) to `registry-gcp.yaml`.
3. Add example Terraform stacks for Azure and GCP in `examples/vulnerable-azure/` and `examples/vulnerable-gcp/`.
4. Update README to clarify current coverage: "AWS: 114 mappings | Azure: 20 mappings | GCP: 20 mappings" (or whatever the actual counts are).

---

## Quick-Start Checklist (Order of Execution)

| # | Task | Priority | Est. Time |
|---|------|----------|-----------|
| 1 | Fix Python version floor | P0 | 15 min |
| 2 | Add severity exit codes | P0 | 1 hr |
| 3 | Remove CRA/DORA from README | P0 | 30 min |
| 4 | Sync Claude skill doc | P0 | 10 min |
| 5 | Restructure README (remove sections) | P1 | 1 hr |
| 6 | Rewrite Report Formats → Usage | P1 | 1.5 hr |
| 7 | Optimize `install_and_test.sh` | P1 | 30 min |
| 8 | Delete `PROJECT_PLAN.md` | P1 | 5 min |
| 9 | Partition registry + add schema validation | P1 | 3 hr |
| 10 | Add CLI test coverage | P1 | 2 hr |
| 11 | Create GitHub Action | P2 | 2 hr |
| 12 | Add pre-commit hook | P2 | 30 min |
| 13 | Validate unverified Checkov IDs | P2 | 2 hr |
| 14 | Add Azure/GCP seed mappings | P3 | 4 hr |
| 15 | Write `CONTRIBUTING.md` | P3 | 1 hr |


**Total estimated effort: ~2-3 focused days** to clear P0+P1 and reach a credible v1.0.
