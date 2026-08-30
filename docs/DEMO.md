# Demo & Screenshot Guide

This document explains how to capture screenshots and terminal recordings for tf-eu-guard demonstrations. The tool is fully functional, but automated screenshot/recording generation is not possible in sandboxed environments.

## Prerequisites

- tf-eu-guard installed (`pip install -e .`)
- Terminal with color support (for dev output)
- Modern web browser (for HTML reports)
- Optional: `asciinema` for terminal recordings

## Quick Demo Commands

### 1. Terminal Output (Dev Report)

```bash
# Scan the vulnerable example
tf-eu-guard scan examples/vulnerable-aws/ --output dev
```

**What to capture**: Terminal showing the rich table with severity colors (CRITICAL red, HIGH orange, MEDIUM yellow, LOW blue), compliance badges (NIS2/GDPR), and resource names.

**Key points to highlight**:
- Multiple findings grouped by severity
- Each finding shows NIS2 and GDPR article mappings
- File paths with line numbers
- Brief remediation guidance

### 2. Security Dashboard (HTML)

```bash
# Generate security dashboard
tf-eu-guard scan examples/vulnerable-aws/ --output security
open scan-report.html  # macOS
# or: xdg-open scan-report.html  # Linux
# or: start scan-report.html     # Windows
```

**What to capture**: Browser window showing:
- Header with scan metadata (timestamp, scan path, finding count)
- Severity breakdown (CRITICAL/HIGH/MEDIUM/LOW counts, possibly with pie chart)
- Finding cards with:
  - Check ID and title
  - Severity badge
  - Compliance framework badges (NIS2 / GDPR / both)
  - Resource name and file path
  - Description
  - Remediation code snippet

**Recommended viewport**: 1280×800 or larger

### 3. Auditor Report (HTML)

```bash
# Generate auditor report
tf-eu-guard scan examples/vulnerable-aws/ --output auditor
open auditor-report.html
```

**What to capture**: Browser window showing:
- Article-by-article structure:
  - **NIS2 Article 21(2)** with sub-sections (a)-(k)
  - **GDPR Article 32(1)** with sub-sections (a)-(d)
  - **GDPR Article 44** (transfers to third countries)
- Each article section showing:
  - Article text or summary
  - OPEN finding count
  - List of affected resources with links

**Key points to highlight**:
- Clean, professional layout suitable for compliance documentation
- Only OPEN findings shown (no "X% passing" percentages)
- Direct mapping from regulation article to infrastructure issue

### 4. Before/After Comparison

```bash
# Vulnerable (before)
tf-eu-guard scan examples/vulnerable-aws/ --output json > vulnerable.json
jq 'length' vulnerable.json
# Expected: 20-30

# Compliant (after)
tf-eu-guard scan examples/compliant-aws/ --output json > compliant.json
jq 'length' compliant.json
# Expected: 0-2
```

**What to capture**: Side-by-side terminal showing the finding count drop.

### 5. Custom Check Demonstration

```bash
# The end2end suite contains hardcoded AWS keys and non-EU regions
tf-eu-guard scan examples/end2end/ --output json | \
  jq '.[] | select(.check_id == "EUGUARD_NIS2_001" or .check_id == "EUGUARD_GDPR_001")'
```

**What to capture**: JSON output showing:
- `EUGUARD_NIS2_001` detecting hardcoded secrets
- `EUGUARD_GDPR_001` detecting us-west-2 region
- Both with NIS2/GDPR article mappings

## Terminal Recording (asciinema)

> **Already recorded:** [`docs/demo/tf-eu-guard-demo.cast`](demo/tf-eu-guard-demo.cast)
> (23 s — a full scan of `examples/vulnerable-aws/`, generated from a real capture via
> [`tools/make_cast.py`](../tools/make_cast.py)). Play it with
> `asciinema play docs/demo/tf-eu-guard-demo.cast` or upload it to asciinema.org to
> embed in the README. Re-record/re-generate with the steps below if the demo changes.

### Installation

```bash
# Ubuntu/Debian
sudo apt-get install asciinema

# macOS
brew install asciinema

# Or via pip
pip install asciinema
```

### Recording a Demo

```bash
# Start recording
asciinema rec tf-eu-guard-demo.cast

# Run demo commands (narrate as you type)
tf-eu-guard scan examples/vulnerable-aws/ --output dev
# Wait for output, scroll if needed
exit  # Stop recording

# Upload to asciinema.org
asciinema upload tf-eu-guard-demo.cast
# Or embed the .cast file in docs
```

### Suggested Recording Script

```bash
# 1. Show help
tf-eu-guard --help

# 2. Scan vulnerable example
tf-eu-guard scan examples/vulnerable-aws/ --output dev

# 3. Show finding count by framework
tf-eu-guard scan examples/vulnerable-aws/ --output json | \
  jq 'group_by(.check_id) | length'

# 4. Filter to GDPR only
tf-eu-guard scan examples/vulnerable-aws/ --output dev --framework gdpr

# 5. Generate all reports
tf-eu-guard scan examples/vulnerable-aws/ --output all
ls -lh *-report.html
```

**Duration target**: 2-3 minutes

## Screenshot Checklist

For README and documentation, capture:

- [x] Terminal: `--output dev` showing colored severity table (`docs/screenshots/vulnerable-scan.png`)
- [x] Browser: `scan-report.html` security dashboard (`docs/screenshots/security-dashboard.png`)
- [x] Browser: `auditor-report.html` showing NIS2 Article 21(2) section (`docs/screenshots/auditor-report.png`)
- [x] Terminal: Finding count comparison (`docs/screenshots/compliant-scan.png` vs `vulnerable-scan.png`)
- [x] Optional: asciinema recording of full workflow (`docs/demo/tf-eu-guard-demo.cast`)

## Tips

1. **Terminal colors**: Use a terminal with good contrast (e.g., iTerm2 with Solarized Dark, or GNOME Terminal with dark theme)
2. **Font size**: Increase terminal font size to 14-16pt for readability in screenshots
3. **Browser zoom**: Use 100% zoom (Cmd+0 / Ctrl+0) for consistent HTML report screenshots
4. **Window size**: Use consistent viewport (1280×800 or 1920×1080)
5. **Annotation**: Add arrows/highlights after capture to emphasize key features

## Real Screenshots (captured 2026-08-30)

The README already embeds real captures from `docs/screenshots/`:

- `vulnerable-scan.png` / `compliant-scan.png` — terminal dev output (rich SVG →
  headless Chromium, via `tools/ansi_to_image.py`)
- `security-dashboard.png` / `auditor-report.png` — Playwright captures of the HTML
  reports, with the live HTML files committed alongside for GitHub-rendered viewing

Regenerate any of them with `tools/ansi_to_image.py` (terminal) or a Playwright
screenshot script (HTML reports).

## Testing the Demo

Before recording/capturing, verify:

1. All three examples directories exist and have .tf files
2. Scans complete without errors
3. HTML reports render correctly in browser
4. Finding counts are reasonable (vulnerable: 20-30, compliant: 0-2)
5. Custom checks fire in end2end suite

```bash
# Quick validation
for dir in examples/vulnerable-aws examples/compliant-aws examples/end2end; do
  echo "Scanning $dir..."
  tf-eu-guard scan "$dir" --output json > /tmp/scan.json
  echo "  Findings: $(jq 'length' /tmp/scan.json)"
done
```

Expected output:
```
Scanning examples/vulnerable-aws...
  Findings: 20-30
Scanning examples/compliant-aws...
  Findings: 0-2
Scanning examples/end2end...
  Findings: ~220
```

## CI/CD Artifact Access

The GitHub Actions workflow uploads HTML reports as artifacts. To download for demo purposes:

1. Push changes and wait for CI to complete
2. Go to Actions tab → latest workflow run
3. Download "compliance-reports" artifact
4. Extract and open HTML files locally

These are production-quality reports generated in a real CI environment, suitable for including in documentation or presentations.
