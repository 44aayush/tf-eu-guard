# tf-eu-guard v0.9.0: security and engineering review

| | |
| --- | --- |
| Scope | Release v0.9.0, commit `abc18e0`: the Python package, custom Checkov checks, mapping registries, CLI, GitHub Action, Dockerfile, CI/release workflows, docs |
| Date | 2026-11-26 |
| Method | Full source read of the security-relevant modules, the test suite and lint run locally, the Docker image built and scanned, 19 hand-made vulnerable fixtures run through the CLI and the hardened Action container, and a Terraform + LocalStack proof of concept |
| Toolchain used | Python 3.12.3, uv 0.13.10, Checkov 3.4.5 (pinned by the project), Terraform 1.17.2, AWS provider 6.74.0, LocalStack 4.9.2 (community), trivy 0.76.2, shellcheck 0.11.0, Docker 29.10.1 |

## 1. Executive summary

tf-eu-guard is a well-engineered project. The defensive work is real: fail-closed parsing, scan-root symlink validation, an isolated Checkov bootstrap, environment scrubbing, secret-value redaction, escaped HTML with a script-free CSP, CSV formula guards, SHA-pinned workflows, hash-locked dependencies, reproducible wheels, OIDC publishing, SBOMs, attestations and a sandboxed Action container. Most of that held up under testing. 1219 tests pass, coverage is 93%, ruff, mypy and shellcheck are clean, and my HTML, CSV and SARIF injection probes were all neutralised.

The weak spot is **the trust model of the CI gate**. The threat that matters for a compliance gate is a pull-request author who wants a red check to turn green. In v0.9.0 that author can do it with files that live next to the code, and with the Action's default inputs:

1. **TEG-01 (High):** commit a `.tf-eu-guard.yaml` (severity overrides, registry overlays, excludes) or a `.tf-eu-guard-waivers.yaml` (expiry 9999-12-31) into the scan root. The gate goes from exit 1 to exit 0. The change is disclosed in the report header, but the build passes.
2. **TEG-02 (Medium):** with `--changed-since`, change a variable default in one file to break a resource in another file. The finding is hidden and the gate passes.
3. **TEG-03 (Medium):** names in the scanned code can inject GitHub workflow commands (`::error`, `::stop-commands`) and ANSI/OSC escape sequences into the job log and the developer's terminal.

The second theme is **residency coverage that passes silently** (TEG-05). A region supplied by the environment, an Azure or GCP location, or Terraform under a hidden directory all produce no residency signal and exit 0. Plan-mode scanning against a real plan closes the first gap; my emulator proof of concept went from 0 to 8 residency findings on the same code (section 6).

None of these is a remote code execution or a data leak. They are integrity problems in a tool whose whole job is integrity, so I would fix TEG-01 to TEG-04 before calling the Action "gate-grade" for untrusted pull requests.

### Scorecard

| Area | Rating | Notes |
| --- | --- | --- |
| Input handling and fail-closed behaviour | Strong | Parsing errors, empty targets, malformed Checkov JSON and broken symlinks all fail closed; excluding every file exits 3 |
| Output safety (HTML, CSV, SARIF, JSON) | Strong | Everything escaped, CSP `default-src 'none'` with no scripts, OWASP CSV guard, SARIF path boundary |
| Output safety (terminal, CI log) | Weak | Control characters pass through (TEG-03) |
| CI gate integrity against untrusted pull requests | Weak | TEG-01, TEG-02, TEG-09 |
| GitHub Action sandbox | Strong | `--network none`, read-only root and workspace, `--cap-drop ALL`, no-new-privileges, symlink-safe copy-back, filtered `$GITHUB_OUTPUT` |
| Release and supply chain | Good | Excellent workflow hygiene; image pulled by mutable tag (TEG-04); base image CVEs (TEG-06) |
| Regulatory mapping quality | Good | Careful hedging; some severity and article inconsistencies (TEG-11) |
| Coverage breadth | Fair | AWS has 186 mappings; Azure 23, GCP 22, Kubernetes 26; no Azure or GCP residency (TEG-05, TEG-10) |
| Tests and code health | Strong | 1219 tests, 93% coverage, strict linting; some long parameter lists (TEG-17) |
| Documentation | Good | Unusually honest about limits; a few drifted statements (TEG-07, TEG-12) |

## 2. Findings

Severity reflects the project's purpose: a CI compliance gate whose input (the pull request) is untrusted.

| ID | Severity | Title | Evidence |
| --- | --- | --- | --- |
| TEG-01 | High | Files committed in the scan root can switch the CI gate off | Reproduced (CLI and Action container) |
| TEG-02 | Medium | `--changed-since` hides findings caused by changes in other files | Reproduced |
| TEG-03 | Medium | Untrusted strings reach the terminal and CI log unsanitised (workflow commands, ANSI/OSC) | Reproduced |
| TEG-04 | Medium | The Action pulls its image by mutable tag and never verifies the published attestation | Code review |
| TEG-05 | Medium | Residency checks pass silently when the region is not in the source | Reproduced |
| TEG-06 | Medium | Runtime image has 61 HIGH OS package findings (18 distinct CVEs, 5 with a fix); no image scan in CI | trivy |
| TEG-07 | Low | Local and pre-commit scans evaluate untrusted expressions unsandboxed; SECURITY.md says "never executed" | Probe and docs |
| TEG-08 | Low | Local module sources bypass the scan-root boundary that symlinks are held to | Reproduced |
| TEG-09 | Low | A forged `--checkov-json` passes every gate with only a warning | Reproduced |
| TEG-10 | Low | Gate coverage equals registry coverage; unmapped failures never gate by default | Analysis |
| TEG-11 | Low | Registry: inconsistent severities, a questionable GDPR Art. 4(12)/33 mapping, gaps, typos | Analysis |
| TEG-12 | Low | Docs drift on `--var-file` and `terraform.tfvars` | Reproduced |
| TEG-13 | Info | `provenance.commit` is always null in the Action | Code review |
| TEG-14 | Info | An `hcl2` module collision breaks Checkov with a cryptic traceback | Observed |
| TEG-15 | Info | Action `path` and `checkov-json` inputs skip the workspace path validation | Code review |
| TEG-16 | Info | The Checkov environment scrub is a denylist | Code review |
| TEG-17 | Info | Code-health items | Code review |

### TEG-01 (High): files committed in the scan root can switch the CI gate off

**Where:** `tf_eu_guard/cli/parser.py:378` (config discovery), `tf_eu_guard/cli/pipeline.py:63` (waiver discovery), `tf_eu_guard/cli/pipeline.py:104` (severity overrides), `action.yml:372` (the Action passes neither `--no-config` nor a trusted config by default).

**What:** with no `--config`, the CLI reads `.tf-eu-guard.yaml` and `.tf-eu-guard-waivers.yaml` from the scanned directory. Both are controlled by whoever writes the pull request. The config can set `severity_overrides` (any check to INFO), `registry_dirs` (overlays that rewrite severities), `exclude` and `waivers`. Waivers have no maximum expiry and no required `file` scope.

**Evidence:**

```text
# vulnerable stack: unencrypted public RDS + public S3 bucket
$ tf-eu-guard scan stack --fail-on-severity HIGH            -> exit 1 (9 findings >= HIGH)

# PR adds stack/.tf-eu-guard.yaml
severity_overrides: {CKV_AWS_17: INFO, CKV_AWS_16: INFO, EUGUARD_NIS2_001: INFO, ...}
$ tf-eu-guard scan stack --fail-on-severity HIGH            -> exit 0

# or PR adds stack/.tf-eu-guard-waivers.yaml
schema_version: 1
waivers:
  - {check_id: CKV_AWS_17, resource: aws_db_instance.orders, owner: nobody, reason: ok, expires: 9999-12-31}
$ tf-eu-guard scan stack --fail-on-severity HIGH            -> exit 0, "23 finding(s) waived"

# same config inside the Action's hardened container (read-only workspace, no network)
$ docker run --rm --network none --read-only ... tf-eu-guard:review stack --fail-on-severity HIGH -> exit 0
```

Excluding every file is handled correctly: Checkov returns no results and the scan exits 3.

**Impact:** the default Action configuration (`fail-on-severity: HIGH`, no `config`, no `trusted-config`) can be bypassed by any pull-request author. The bypass is listed under "scan settings that reduce findings", but a required status check only looks at the exit code. The README (line 486) and `docs/limitations.md` acknowledge the waiver risk and offer `trusted-config`, but the secure behaviour is opt-in and the `config` input's description does not mention implicit discovery.

**Recommendations:**

1. In the Action, do not read any configuration from the checkout unless the workflow asks for it. Pass `--no-config` plus a new `--no-waiver-discovery` when neither `config` nor `trusted-config` is set. Alternatively, on `pull_request` events read the base-branch copy (`git show "origin/$GITHUB_BASE_REF:<path>/.tf-eu-guard.yaml"`) into `RUNNER_TEMP` and use it as the trusted config.
2. Add a CLI `--strict` / `--fail-on-weakening` gate that exits 1 when any weakening setting came from a discovered file, and enable it in the Action by default.
3. Bound waivers: a `max_waiver_days` setting (default 180, set from the trusted config), and reject or warn on waivers without `file`.
4. Document a CODEOWNERS rule for `**/.tf-eu-guard*.yaml` and the registry overlay directories in the Action section of the README.

### TEG-02 (Medium): `--changed-since` hides findings caused by changes in other files

**Where:** `tf_eu_guard/cli/pipeline.py:229` (`inside()` filters by the finding's own file).

**What:** Terraform's unit of meaning is the module directory, not the file. A variable default, a local, a `terraform.tfvars` or a called module can change the outcome for a resource in an untouched file. `--changed-since` removes those findings from the gate as well as from the display.

**Evidence:**

```text
main:  variables.tf  variable "encrypt" { default = true }
       rds.tf        storage_encrypted = var.encrypt
PR:    variables.tf  default = false       (rds.tf untouched)

$ tf-eu-guard scan . --fail-on-severity HIGH                         -> exit 1 (CKV_AWS_16 HIGH in rds.tf)
$ tf-eu-guard scan . --fail-on-severity HIGH --changed-since main    -> exit 0
  "Reporting only findings in 1 file(s) changed since main; 10 finding(s) in unchanged files hidden"
```

**Recommendations:** treat a change to any `.tf`, `.tfvars` or `.hcl` file in a directory as a change to every finding in that directory, and to every directory whose local module sources resolve to it. Simpler and safer still: let the gate always use the full finding set and have `--changed-since` filter only what is shown, or require an explicit `--changed-since-gates` opt-in with a warning.

### TEG-03 (Medium): untrusted strings reach the terminal and CI log unsanitised

**Where:** `tf_eu_guard/reporting/dev_report.py:57` and `:200`, plus `waived.py`, `baselined.py`, `suppressed.py` and the stderr messages in `cli/pipeline.py` that print check IDs, resources and file paths. `rich.markup.escape()` neutralises Rich markup (`[...]`), not control characters.

**What:** resource names (for Kubernetes, `metadata.name` is free text in YAML), file names and waiver text from the checkout are printed verbatim. The manifest does not need to be valid Kubernetes; Checkov parses it anyway.

**Evidence:**

```yaml
metadata:
  name: "web\n::error title=FORGED::tf-eu-guard found 0 issues - safe to merge\n::stop-commands::x"
```

```text
$ tf-eu-guard scan k8s --iac-type kubernetes --output dev
    Resource: Deployment.default.web
::error title=FORGED::tf-eu-guard found 0 issues - safe to merge
::stop-commands::x
```

On a GitHub runner the first line becomes an annotation on the pull request, and `::stop-commands::x` disables workflow-command processing for the rest of the step, so the Action's own `::error::` and `::warning::` lines stop working. A second probe with `\e]8;;https://evil.example\e\\` (OSC 8 hyperlink) and `\e[2K\e[1A\e[32mALL CHECKS PASSED` produced 17 raw escape sequences in the `dev` output: a clickable link and a green line drawn over the finding. `dev` is the Action's default output and the pre-commit hook's output. The Markdown summary (newlines become spaces), CSV, JSON and SARIF outputs were not affected, and the HTML reports escaped a separate `<img onerror>` / `<script>` / attribute-breakout payload in all three formats.

**Recommendations:**

1. Add one `sanitize_untrusted()` helper that renders C0 controls except tab, DEL, C1 controls (0x80-0x9F) and the Unicode bidi overrides (U+202A-U+202E, U+2066-U+2069) as visible escapes such as `\n` and `\x1b`. Apply it in every terminal and stderr renderer, before `escape()`.
2. In `action.yml`, bracket the container run with a random token: `token=$(openssl rand -hex 16); echo "::stop-commands::$token"; docker run ...; echo "::$token::"`. This is GitHub's documented defence against log injection, and it also protects against anything Checkov itself prints.
3. Add regression tests with hostile `metadata.name` values and file names.

### TEG-04 (Medium): the Action pulls its image by mutable tag and never verifies the attestation

**Where:** `action.yml:199` pulls `ghcr.io/44aayush/tf-eu-guard:${ACTION_REF}`; `.github/workflows/publish.yml` (the `image` job) pushes that tag and creates a build-provenance attestation that nothing consumes.

**What:** consumers usually pin the Action by tag (`uses: 44aayush/tf-eu-guard@v0.9.0`). The composite steps are then fixed, but the container that actually scans the code is whatever the GHCR tag points to on the day of the run. Anyone holding a `packages: write` token for the repository, or the maintainer account, can retag it. Consumers who pin by commit SHA get a local build, which is safe but slow.

**Recommendations:** have the release workflow record the pushed digest in the tagged commit (for example an `IMAGE_DIGEST` line in `action.yml` written before the tag is cut), and pull `ghcr.io/...@sha256:<digest>`. Or verify before running: `gh attestation verify oci://ghcr.io/44aayush/tf-eu-guard:$ref --repo 44aayush/tf-eu-guard`, falling back to a local build on failure. Enable tag immutability on the GHCR package if it is available to the account.

### TEG-05 (Medium): residency checks pass silently when the region is not in the source

**Where:** `tf_eu_guard/checks/gdpr/data_residency.py:81` (an unset provider region returns UNKNOWN), `tf_eu_guard/checks/regions_conf.py` (AWS only), `tf_eu_guard/checkov/process.py:116` (ignored directories).

**Evidence (each case exits 0 with no residency finding and no warning):**

| Case | Source | Result |
| --- | --- | --- |
| No `provider "aws"` region; region comes from `AWS_REGION` or a profile at apply time | `terraform { required_providers { aws = ... } }` plus resources | 0 residency findings |
| Azure | `azurerm_resource_group` and `azurerm_storage_account` in `location = "eastus"` | 0 residency findings |
| GCP | provider `region = "us-central1"`, bucket `location = "US"` | 0 residency findings |
| Hidden directory | the whole vulnerable stack under `.prod/` | 0 findings of any kind |
| Global services | `aws_cloudfront_distribution` with `price_class = "PriceClass_All"` (edge caches outside the EU) | no signal |

What works well: provider aliases, `locals`, `terraform.tfvars` and an unresolved `var.region` are all handled and fail closed where intended. `docs/limitations.md` already says Azure and GCP residency are not covered, but the README feature list cites GDPR Art. 44 and a "configurable region residency policy" without saying they are AWS-only, and the missing-region and hidden-directory cases are not documented.

**Recommendations:**

1. Add a policy check: "AWS resources present but no provider block sets a region". Report it as MEDIUM and fail-closed, consistent with the rest of the residency policy.
2. Add Azure (`location`) and GCP (`region`, `location`, multi-region `US` / `ASIA`) residency tables and checks, mirroring `regions.py`.
3. Warn on stderr when `.tf` files exist under directories Checkov skips. `iter_scanned_files` already walks the tree, so the information is free.
4. Document plan mode as the authoritative residency scan. With AWS provider 6.x every resource carries a computed `region` in the plan, and `EUGUARD_POLICY_002` / `GDPR_003` fire on it (section 6).

### TEG-06 (Medium): runtime image has 18 HIGH OS CVEs and no image scan in CI

**Where:** `Dockerfile:20` (`python:3.12-slim@sha256:f77ac9e...`, Debian 13.7).

**Evidence:** `trivy image --severity HIGH,CRITICAL tf-eu-guard:review`: 0 CRITICAL and 61 HIGH package findings in OS packages, which come down to 18 distinct CVEs. 5 of them have a fixed version available (openssl/libssl3t64, zlib1g, libzstd1, libpcre2-8-0, apt). Many are in packages the scanner never needs at runtime (apt, perl-base, login, mount, util-linux). On the Python side, `ecdsa` CVE-2024-23342 is already covered by `dependency-exceptions.json`.

**Recommendations:** add a CI job running `trivy image --ignore-unfixed --exit-code 1 --severity HIGH,CRITICAL` on the built image. Merge Dependabot's base-digest bumps promptly, or rebuild on a schedule. Consider a smaller final stage (distroless Python, or removing apt and perl from the slim image), which also shrinks the 535 MB image.

### TEG-07 (Low): local and pre-commit scans evaluate untrusted expressions unsandboxed

**Where:** `SECURITY.md:46` ("Scanned code is only read, never executed"); `dependency-exceptions.json` (asteval PYSEC-2026-3807 and GHSA-9w56-46f6-3qhx, marked "Reachable").

**What:** Checkov renders Terraform expressions from the scanned code with asteval 1.0.6. The exceptions file correctly says this is reachable, which contradicts SECURITY.md. The Action contains it with the hardened container; the CLI, the pre-commit hook and pip-installed CI jobs do not.

**My reachability probe:** Checkov builds `Interpreter(use_numpy=False, minimal=True)` (`checkov/terraform/graph_builder/variable_rendering/safe_eval_functions.py`). In that configuration `raise` is not implemented, and numpy (the ctypes vector fixed in 1.0.9) is not exposed. So the two known escape routes look closed, which is a better story than the exceptions file currently tells. `open` (read-only) is still exposed to expressions. tf-eu-guard never copies attribute values into reports, so I found no channel for data to leave through its outputs.

**Recommendations:** correct SECURITY.md (expressions are evaluated in Checkov's restricted interpreter; scan untrusted code in the container). Record the probe above in the exceptions' reachability text. Document a one-line `docker run` for scanning untrusted checkouts locally, or add a `tf-eu-guard scan --sandbox` wrapper.

### TEG-08 (Low): local module sources bypass the scan-root boundary

**What:** a symlink pointing outside the scan root is rejected with exit 2 (good), but `module "m" { source = "../outside" }` makes Checkov read and report the same files. My fixture returned 16 findings with `file_path: /../outside/main.tf`. The impact is small: only Terraform files are read, and the Action mounts only the workspace. Still, the README's "symlink boundary" wording implies a stronger boundary than exists.

**Recommendation:** resolve local module sources and warn, or reject behind an `--allow-modules-outside-root` opt-in, when they leave the root. Or document that the boundary covers symlinks only.

### TEG-09 (Low): a forged `--checkov-json` passes every gate

```text
$ tf-eu-guard scan --checkov-json forged.json --fail-on-severity LOW --fail-on-unmapped
Warning: no EUGUARD_* check appears in the Checkov JSON ...
✓ No compliance findings!                                        -> exit 0
```

In the Action the file comes from the workspace, so a pull request controls it. **Recommendation:** when any gate flag is set, make "no EUGUARD_* check present" and `resource_count == 0` fatal (exit 3) unless `--allow-partial` is given. Say plainly in the docs that `--checkov-json` is only as trustworthy as whoever produced the file.

### TEG-10 (Low): gate coverage equals registry coverage

The registry holds 276 entries (AWS 186, Azure 23, GCP 22, Kubernetes 26, secrets 19). Unmapped failures never gate unless `--fail-on-unmapped` is set (`cli/gating.py:77`), and the Action has no input for that flag. Example: an `aws_ssm_parameter` of `type = "String"` holding a password raises `CKV2_AWS_34`, which is unmapped, so it is never gated. **Recommendations:** add a `fail-on-unmapped` Action input and an `--unmapped-severity LEVEL` option. Publish a per-release table of which Checkov checks in the pinned version are mapped, deliberately unmapped (with a reason) or not yet triaged.

### TEG-11 (Low): registry quality

- **Inconsistent severities for the same control:** encryption at rest is HIGH for RDS (`CKV_AWS_16`, `registry-aws.yaml:459`) but CRITICAL for Aurora (`CKV_AWS_96`, `:1108`), Elasticsearch (`CKV_AWS_5`) and Neptune (`CKV_AWS_44`). EBS (`CKV_AWS_3`) is HIGH. Write a severity rubric and test it, for example "same control family and same data exposure means the same severity".
- **Questionable legal mapping:** `CKV_AWS_288` (an IAM policy allowing data exfiltration) cites GDPR Art. 4(12), which is the definition of a personal data breach, and Art. 33, which is breach notification (`registry-aws.yaml:67`). A permissive policy is a security-of-processing gap (Art. 32(1)(b), NIS2 Art. 21(2)(i)). It is not a breach and does not trigger Art. 33. I recommend removing both citations, or moving them to the risk text as context.
- **Gaps and asymmetries:** `CKV2_AWS_30` (Postgres RDS query logging) is mapped but `CKV2_AWS_27` (Aurora Postgres query logging) is not. `CKV2_AWS_34` (SSM parameter encryption) is unmapped.
- **Typo:** "weakensing" appears four times (`registry-aws.yaml:337`, `:1777`, `:2724`, `registry-kubernetes.yaml:110`) and ships in every report. Add codespell to the lint job.

### TEG-12 (Low): docs drift on `--var-file` and `terraform.tfvars`

`docs/limitations.md:65` says "there is no `--var-file` support", but the flag exists. `docs/limitations.md:166` says variables set only in a `.tfvars` file are unresolved unless passed with `--var-file`. In my test, Checkov loaded `terraform.tfvars` automatically: `region = "us-east-1"` set only there produced `EUGUARD_GDPR_002` without `--var-file`. The accurate statement is that auto-loaded files (`terraform.tfvars`, and probably `*.auto.tfvars`, which I did not test) are resolved, and other files need `--var-file`.

### TEG-13 (Info): `provenance.commit` is always null in the Action

The image has no git, so `provenance.py:95` returns null. The commit is the single most useful provenance field for an auditor. Pass `GITHUB_SHA` into the container (`-e TF_EU_GUARD_COMMIT=$GITHUB_SHA` or a `--commit` flag) and record where the value came from.

### TEG-14 (Info): `hcl2` module collision

Installing `terraform-local` into the same environment pulled in `python-hcl2`, which overwrote the `hcl2` module provided by Checkov's `bc-python-hcl2`. Every scan then failed with `ImportError: cannot import name 'START_LINE' from 'hcl2'` and exit 3. Failing closed is correct. Add a startup self-check with a plain-language message, and make `uv tool install` / pipx the primary install path in the README, since many IaC tools depend on `python-hcl2`.

### TEG-15 (Info): two Action inputs skip workspace path validation

`action.yml:259` passes `checkov-json` and the positional `path` through unchanged, while `config`, `waivers` and `baseline` go through `ws_rel`. The container mount limits the impact. Validate them the same way for consistency and clearer errors.

### TEG-16 (Info): the Checkov environment scrub is a denylist

`checkov/process.py:93` removes known `CKV_*`, `BC_*`, `PRISMA_*` and `GIT_*` variables. Checkov reads many more environment variables, and new releases add some. I found no exploitable variable (`CHECKOV_CREATE_GRAPH=False` had no effect), but an allowlist (PATH, HOME, LANG/LC_*, TMPDIR, proxy and CA-bundle variables, plus the two residency variables) would make this robust to future Checkov versions.

### TEG-17 (Info): code health

- `cli/pipeline.py:294`: `filter_findings_by_framework` mutates `EnrichedFinding` objects in place, and those objects are shared with the unfiltered result. Use `dataclasses.replace` so that API callers of `run_scan` cannot observe framework-filtered articles on objects they still hold.
- `cli/reports.py` threads the same 10 to 12 parameters through five layers. A `ReportContext` dataclass would remove about 150 lines and a class of "forgot to pass X to format Y" bugs.
- `checkov/process.py:277` treats only `./` and `../` as local module sources, so absolute local paths are reported as "remote".
- `--json-format array` is deprecated but is still the default. Schedule the switch for 0.10 and warn now when the format is implicit.
- `tools/check_dependency_exceptions.py` and `tools/check_sbom_lock.py` have 0% coverage although they are supply-chain gates in CI.
- `checkov_runner.py` re-exports many private names for compatibility. Plan a deprecation window.

## 3. What is done well (keep it)

- **Fail-closed by default:** Checkov parsing errors, a missing `summary`, an empty target, a `check_type` mismatch and malformed findings all raise. `--allow-partial` is an explicit, logged opt-out.
- **Isolated scanner:** `python -I`, patched `.checkov.yml` discovery, a trusted cwd outside the checkout, `--skip-download`, platform keys scrubbed even with `--online`.
- **Git safety:** `core.fsmonitor=false`, `core.hooksPath=/dev/null`, `GIT_*` scrubbed, and no working-tree comparisons that could trigger filter drivers.
- **Secret handling:** secrets-framework records are reduced to an allowlist of fields; values, code blocks and hashes never reach a report. In my tests, secrets passed through locals, `join()`, variable defaults, connection strings and Slack webhooks were all detected.
- **Output encoding:** HTML is escaped everywhere and carries `default-src 'none'` with no scripts. Guideline URLs are restricted to http(s). CSV has an OWASP formula guard (confirmed with a `=HYPERLINK(...)` file name). SARIF keeps paths inside the repository.
- **Action sandbox:** no network, read-only root and workspace, all capabilities dropped, no-new-privileges, the runner's uid, symlink-safe copy-back, regex-filtered `$GITHUB_OUTPUT` and a size-capped job summary. shellcheck reports only two style notes on roughly 300 lines of bash.
- **Release pipeline:** every action pinned by SHA, zizmor at the auditor persona, checksum-verified actionlint, hash-locked dependencies, a lock-drift check, a byte-for-byte reproducible wheel, a tag-ancestry check, OIDC trusted publishing in a job that never checks out code, SBOM checked against the lock, build-provenance attestations, and dependency exceptions with owners and expiry dates.
- **Honesty in reporting:** unmapped, suppressed, waived and baselined findings are never dropped silently; weakening settings are printed in every format; legal claims are carefully hedged; limitations are documented in one place.
- **Tests:** 1219 passing, 93% line coverage, real-Checkov tests behind `TFEG_RUN_CHECKOV=1`, schema validation for SARIF, and doc-count drift checks.

## 4. Evidence log

| Check | Command | Result |
| --- | --- | --- |
| Unit and integration tests | `TFEG_RUN_CHECKOV=1 pytest` | 1219 passed, 7 skipped, 93% coverage, 190 s |
| Lint, format, types | `ruff check .`, `ruff format --check .`, `mypy tf_eu_guard tools` | clean |
| Action bash | `shellcheck -S style` on the extracted `run:` block and the repo scripts | 2 style notes (SC2129) |
| Image build | `docker build .` (hash-locked, two-stage) | OK, 535 MB, runs as user `tfeguard` |
| Image CVEs | `trivy image --severity HIGH,CRITICAL` | 0 CRITICAL; 61 HIGH OS package findings (18 distinct CVEs, 5 fixable); 1 HIGH in Python (known exception) |

Lab fixtures (each a small Terraform or Kubernetes directory; the snippets are in the findings above):

| # | Scenario | Result | Finding |
| --- | --- | --- | --- |
| E0 | Unencrypted public RDS and public S3 bucket | 23 mapped findings, exit 1 at HIGH | baseline |
| E1 | E0 plus discovered config with `severity_overrides` | exit 0 (CLI and container) | TEG-01 |
| E2 | E0 plus discovered waivers expiring 9999-12-31 | exit 0 | TEG-01 |
| E3 | Config excluding every file | exit 3 (fail closed) | good |
| E4 | `source = "../outside"` module | 16 findings from outside the root | TEG-08 |
| E5a-e | Residency: no provider region, Azure/GCP, aliases, locals, tfvars | aliases, locals, tfvars detected; no-region, Azure, GCP silent | TEG-05, TEG-12 |
| E6 | Secrets via locals, `join()`, variable default, Lambda env, SSM | all detected except the plaintext SSM parameter (unmapped) | TEG-10 |
| E7 | K8s `metadata.name` with `\n::error` | workflow commands at line start in `dev` output | TEG-03 |
| E8 | Two modules with `aws_s3_bucket.this` | addresses are module-qualified, so waivers stay scoped | good |
| E9 | Stack inside `.prod/` | 0 findings, exit 0, no warning | TEG-05 |
| E10 | `--changed-since` with a cross-file change | exit 0 instead of 1 | TEG-02 |
| E11 | OSC 8 and CSI sequences in a name | 17 raw escape sequences in the terminal output | TEG-03 |
| E12 | File name starting with `=HYPERLINK` in CSV | neutralised | good |
| E13 | Forged clean `--checkov-json` with every gate on | exit 0, warning only | TEG-09 |
| E14 | `<img onerror>`, `<script>` and an attribute breakout in K8s names, `--output all` | escaped in all three HTML reports; CSP present | good |

## 5. Prioritised plan

| When | Items |
| --- | --- |
| Before the next release (0.9.1) | TEG-01 (Action default to no discovery and a `--strict` gate), TEG-03 (sanitiser plus `stop-commands` token), TEG-02 (directory-granular changed set, or display-only filtering), TEG-07 and TEG-12 (docs corrections), TEG-11 typos |
| 0.10 | TEG-04 (digest-pinned or attested image), TEG-06 (image scan in CI, slimmer base), TEG-05 (missing-region check, Azure/GCP residency, hidden-directory warning), TEG-09, TEG-11 severity rubric and mapping fixes, the JSON object format as default |
| Later | TEG-10 coverage programme, TEG-08, TEG-13 to TEG-17, and the emulator test tier below |

## 6. Would it be a good idea to test the project with an AWS emulator?

**Yes, as an additional test tier, not as a replacement for the static tests.** tf-eu-guard's core never talks to AWS, so the emulator's value is in producing realistic inputs and ground truth that a static fixture cannot.

### Why

1. **Real plan JSON drives plan mode.** `examples/vulnerable-aws-plan/plan.json` is a committed, hand-curated artefact. An emulator lets CI generate plans with real Terraform and real provider versions on every run, so drift in the plan format (for example AWS provider 6.x adding a computed `region` to every resource) is caught. I verified this mattered:

   | Same code (no region in source; `AWS_REGION=us-east-1` at plan time) | Findings | Residency findings |
   | --- | --- | --- |
   | Source scan | 13 | 0 |
   | Plan scan (Terraform 1.17.2, AWS provider 6.74.0, LocalStack 4.9.2) | 21 | 8 (`EUGUARD_POLICY_002` and `EUGUARD_GDPR_003` on all 4 resources) |

   That one run turns TEG-05's worst case into a tested, documented path.
2. **Ground-truth differential testing.** Apply the vulnerable fixture, read the real resource state back through the AWS API, and compare it with the findings. In my run boto3 confirmed `BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets = false` and `SqsManagedSseEnabled = false`, matching CKV_AWS_53 to 56 and the SQS finding. Run continuously, this measures false positives and false negatives, which is the evidence an auditor will ask for.
3. **Remediation snippets that actually apply.** The registry's remediation text and `examples/compliant-aws` can be applied to the emulator, which proves they are valid, deployable Terraform rather than plausible-looking text.
4. **End-to-end Action tests with no cloud account:** no credentials, no cost, no risk of touching a real account, and the same result on every fork.
5. **Module and variable semantics:** plans expand modules, including remote ones, so emulator plans are the natural regression suite for TEG-02 and TEG-08 style issues.

### What it will not do, and the caveats

- It does not validate the legal mappings, and a clean emulator run says nothing about compliance.
- **Fidelity is partial:** LocalStack community does not enforce IAM by default, and RDS, CloudFront, EKS and some others are Pro-only for `apply`. `plan` works for any resource type because it makes almost no API calls. I also saw a perpetual diff on `aws_dynamodb_table` (replace on every apply), so assert on plans and on a small set of read-backs, not on idempotent applies.
- **Licensing changed:** `localstack/localstack:latest` (2026.11) refuses to start without `LOCALSTACK_AUTH_TOKEN` (exit 55). The tag `4.9` (community 4.9.2) still runs without a token. For an open-source CI, pin `localstack/localstack:4.9` by digest, or use `motoserver/moto` (Apache-2.0; I confirmed it answers on port 5000), which covers S3, SQS, DynamoDB, KMS, IAM and more.
- `terraform init` needs the provider from the registry. Cache it (`TF_PLUGIN_CACHE_DIR`) and commit a `.terraform.lock.hcl` for the emulator fixtures, so runs are reproducible.

### How

1. **Keep emulator wiring out of the scanned fixtures.** Copy the fixture into a temporary directory and add a provider override file there. Committing it into a fixture would trigger `CKV_AWS_41` (hard-coded keys) and pollute the scan.

   ```hcl
   # localstack_override.tf, generated into the temporary copy only
   provider "aws" {
     access_key                  = "test"
     secret_key                  = "test"
     skip_credentials_validation = true
     skip_metadata_api_check     = true
     skip_requesting_account_id  = true
     s3_use_path_style           = true
     endpoints {
       s3       = "http://127.0.0.1:4566"
       sqs      = "http://127.0.0.1:4566"
       dynamodb = "http://127.0.0.1:4566"
       sts      = "http://127.0.0.1:4566"
       iam      = "http://127.0.0.1:4566"
     }
   }
   ```

   `tflocal` (terraform-local) generates the same file automatically, but install it in its own environment (TEG-14), and note that LocalStack now marks it deprecated in favour of `lstk terraform`.

2. **A pytest tier, gated like the existing real-Checkov tests:**

   ```python
   # tests/emulator/test_plan_residency.py
   import os
   import shutil
   import subprocess

   import pytest

   pytestmark = pytest.mark.skipif(
       os.environ.get("TFEG_RUN_EMULATOR") != "1", reason="needs LocalStack/moto and terraform"
   )


   def _plan(fixture, tmp_path, region):
       work = tmp_path / "work"
       shutil.copytree(fixture, work)
       shutil.copy("tests/emulator/localstack_override.tf", work)
       env = {**os.environ, "AWS_REGION": region}
       for args in (["init", "-input=false"], ["plan", "-input=false", "-out=tfplan"]):
           subprocess.run(["terraform", *args], cwd=work, env=env, check=True)
       shown = subprocess.run(
           ["terraform", "show", "-json", "tfplan"],
           cwd=work, env=env, check=True, capture_output=True, text=True,
       )
       plan = work / "plan.json"
       plan.write_text(shown.stdout)
       return plan


   def test_env_region_is_caught_in_plan_mode(tmp_path):
       from tf_eu_guard import scan

       plan = _plan("tests/emulator/fixtures/no-provider-region", tmp_path, "us-east-1")
       result = scan(plan, iac_type="terraform_plan", no_config=True)
       ids = {f.check_id for f in result.findings}
       assert {"EUGUARD_POLICY_002", "EUGUARD_GDPR_003"} <= ids
   ```

   Add apply-and-read-back tests for a few high-value controls (S3 public access block, SQS and SNS encryption, DynamoDB SSE, KMS rotation), asserting that a finding exists exactly when boto3 reports the insecure state.

3. **A CI job using a service container:**

   ```yaml
   emulator:
     runs-on: ubuntu-24.04
     timeout-minutes: 20
     permissions:
       contents: read
     services:
       localstack:
         image: localstack/localstack:4.9@sha256:<pin-the-digest>
         ports: ["4566:4566"]
         env:
           SERVICES: s3,sqs,dynamodb,sts,iam,kms
     steps:
       - uses: actions/checkout@<sha> # v7
         with:
           persist-credentials: false
       - uses: hashicorp/setup-terraform@<sha> # pin
         with:
           terraform_version: 1.17.2
           terraform_wrapper: false
       - run: pip install --require-hashes -r requirements.lock -r requirements-dev.lock && pip install --no-deps -e .
       - run: pytest tests/emulator
         env:
           TFEG_RUN_EMULATOR: "1"
           TF_PLUGIN_CACHE_DIR: ${{ runner.temp }}/tf-plugins
   ```

4. **Matrix the provider version** (for example `~> 5.0` and `~> 6.0`). The plan shape differs, and plan-mode residency only works on 6.x.

**Recommendation:** add the plan-only emulator tier first. It is cheap, stable, needs no Pro features and directly covers TEG-05. Add apply-and-read-back differential tests for about ten high-signal controls after that. Do not gate releases on emulator applies until their flakiness has been measured.
