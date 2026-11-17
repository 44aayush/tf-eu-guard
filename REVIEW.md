# tf-eu-guard 0.7.1 — end-to-end review

Reviewed at commit `bb92c4a` (tag `v0.7.1`) on 2026-11-12.

- Fixes: **[TASKS.md](TASKS.md)** (40 tasks: 7 high, 20 medium, 13 low)
- New functionality: **[NEW_FUNC.md](NEW_FUNC.md)** (20 items)

## Verdict

The idea is good and, as far as the search found, not duplicated in open source. The engineering around it is careful: hash-locked dependencies, commit-pinned workflows, trusted publishing, more than 500 tests, and documentation that is unusually honest about what an IaC scanner cannot prove.

The tool is not yet reliable enough for its stated purpose, which is producing results someone can cite in audit preparation. A clean result cannot currently be trusted, for three reasons I reproduced:

1. A comment in the scanned code removes any finding without trace, including the tool's own custom checks ([T-01](TASKS.md#t-01--inline-checkovskip-comments-silently-remove-findings)).
2. The custom secret checks flag secure configurations and miss real credentials ([T-04](TASKS.md#t-04--euguard_nis2_001-flags-secure-secret-references-as-hardcoded), [T-05](TASKS.md#t-05--euguard_nis2_002-flags-benign-manifests-and-misses-real-credentials)).
3. The residency checks see only AWS provider blocks, so data placed elsewhere per resource or by replication is missed ([T-07](TASKS.md#t-07--residency-checks-miss-per-resource-regions-and-cross-region-replicas)).

Two further points limit adoption. The default policy fails every deployment outside the AWS European Sovereign Cloud, including `eu-central-1`, and cannot be configured ([T-06](TASKS.md#t-06--sovereign-cloud-only-policy-is-on-by-default-at-high-and-cannot-be-configured)). On Windows the default report crashes when output is redirected, and scans fail when the code is on a different drive from Python ([T-02](TASKS.md#t-02--windows-scan-fails-when-the-target-is-on-another-drive), [T-03](TASKS.md#t-03--windows-default-dev-report-crashes-when-output-is-redirected)).

The `Development Status :: 5 - Production/Stable` classifier is premature. Beta is the accurate label until the high-severity tasks are closed.

| Area | Assessment |
| --- | --- |
| Idea | Sound; addresses a real gap between scanner output and regulatory language |
| Uniqueness | No equivalent open-source project found; the advantage is thin because it rests on about 5,700 lines of mapping data |
| Build, release and supply chain | Strong |
| Test suite | Strong on Linux paths; no Windows or macOS coverage |
| Accuracy of custom checks | Weak; false positives and false negatives reproduced |
| Trustworthiness of a clean result | Weak until suppressions are reported |
| Regulatory depth | Moderate; article-letter granularity, three coverage labels overclaim |
| Documentation | Good and candid, with some drift |

## Scope and method

I read every Python module in `tf_eu_guard/`, the three workflows, `action.yml`, the Dockerfile, the packaging and lock files, the tooling scripts, and the main documents. I sampled the four registries and the tests but did not audit all 251 mappings individually.

I then ran the project on the review machine (Windows 11, Python 3.14.10, Checkov 3.3.29) in a virtual environment created with uv:

| Check | Result |
| --- | --- |
| Test suite with Checkov-backed tests enabled | 524 passed, 4 failed, 4 skipped; 88% coverage. All four failures are Windows-specific (T-02, T-03, T-23) |
| `ruff check` and `ruff format --check` | Clean |
| `mypy` | Clean in both the CI scope and the commit-hook scope |
| zizmor on workflows and action | 7 medium findings, all the same rule (checkout keeps credentials); no high findings |
| actionlint | Clean |
| bandit on the package | 1 medium, a false positive (`yaml.load` with a `SafeLoader` subclass); 2 low |
| pip-audit on `requirements.lock` | Only the three advisories the project already records as exceptions |
| Pinned action commits | All 7 match genuine upstream release tags |
| Purpose-built fixtures | About a dozen scenarios scanned through the CLI to confirm or refute suspected defects; fixtures removed afterwards |

**Not verified.** The Docker daemon was not running, so the image build and the GitHub Action were assessed by reading only. Nothing was run on Linux or macOS. I did not test an upload to GitHub Code Scanning, Checkov's platform mode, or the PyPI and GitHub environment settings, which are not visible in the repository. I did not read the two `asteval` advisories. The legal accuracy of individual mappings is outside what a code review can settle.

## 1. The project idea

tf-eu-guard runs Checkov over Terraform source, Terraform plan JSON or Kubernetes manifests. It joins each failed check to a hand-written registry that says which NIS2 Art. 21(2) and GDPR Art. 32/44 clauses the check is evidence for, with a risk explanation, a remediation snippet and a severity. It adds four checks of its own for data residency and hardcoded secrets. Output is a terminal report, three HTML reports (developer, security, auditor), JSON and SARIF, with exit codes for CI gating. It ships as a PyPI package, a GitHub Action and a pre-commit hook.

The problem is real. Scanners report "bucket not encrypted"; auditors ask about Art. 21(2)(h). Translating between the two by hand is slow, and the commercial platforms that automate it are paid products. Putting the mapping in a reviewable, versioned file is the right design, and the README is correct that the registry, not the wrapper, is the product.

Three weaknesses are inherent to the idea and should shape the roadmap:

- **The value is the data.** The code is a thin layer over Checkov. Any established scanner that accepts custom compliance frameworks could absorb the mapping.
- **Static configuration is a small part of both regulations.** The project says so clearly in `docs/limitations.md`. The risk is that readers of a report do not read that file.
- **The mapping makes legal-adjacent claims.** Its credibility depends on review by someone with audit or legal standing, which the repository does not record.

## 2. Good or bad, unique or duplicate

**Good, with reservations stated in the verdict.**

**Unique in open source, as far as the search found.** The search was run by a Haiku 5.5 agent, about 25 concept-only queries with pages opened to confirm. That supports "not found", not "does not exist".

| Project | What it is | Overlap | Difference | Source |
| --- | --- | --- | --- | --- |
| Prowler | Open-source cloud scanner with a NIS2 framework for AWS (120 requirements) | NIS2 mapping | Scans live accounts, not IaC | Confirmed |
| Kyverno NIS2 guidance (Nirmata, Elastisys) | Blog with four example policies mapped to Art. 21(2) | NIS2 for Kubernetes | Admission-time policies, not a scanner; four examples | Confirmed |
| readystack eu-data-residency-lint | npm tool flagging non-EEA regions in Terraform, Bicep and YAML | Residency check | GDPR transfers only; no NIS2; paid for CI use | Confirmed |
| nis2shield/infrastructure | Terraform modules and Helm chart with a NIS2 matrix | NIS2 and Terraform | Reference infrastructure, not a scanner | Confirmed |
| fabriziosalmi/nis2-public | External-surface scanner with a NIS2 checklist | NIS2 | Does not read IaC | Confirmed |
| Kubescape | Kubernetes scanner with NSA, MITRE and CIS frameworks | Manifest scanning | No NIS2 or GDPR framework | Confirmed |
| Trivy | Scanner with `--compliance` reports | Compliance reporting | No NIS2 or GDPR specification shipped | Confirmed |
| Checkov (open-source CLI) | The engine tf-eu-guard wraps | Detection | No NIS2 or GDPR mapping found in its README | Confirmed, policy index not read |
| Terrascan | IaC scanner | Detection | Archived on 2025-11-20 | Confirmed |
| CISO Assistant and similar | Governance platforms with NIS2 frameworks | NIS2 | Not IaC scanning | Confirmed |
| Aikido, Wiz, Vanta | Commercial products | NIS2 framework claims | Paid | Search snippet only |
| Prisma Cloud | Commercial platform behind Checkov | Sells compliance-standard mappings | Paid; mapping not in the free CLI | My own knowledge, not checked online |

Two things follow. First, the closest open-source NIS2 work targets live cloud accounts (Prowler) or admission control (Kyverno), so the static-IaC position is open. Second, Trivy and Kubescape both accept custom compliance frameworks, to my knowledge. The likeliest way this project is displaced is someone publishing a NIS2 specification for one of them. [N-17](NEW_FUNC.md#n-17--publish-the-registry-in-other-tools-formats) suggests doing that from this registry first.

The package's own PyPI page appeared in the concept searches, so it is discoverable for these terms.

## 3. Code fixes

The full list with locations, evidence and fixes is in **[TASKS.md](TASKS.md)**. The findings that most affect whether a result can be trusted:

| ID | Finding | How it was confirmed |
| --- | --- | --- |
| T-01 | Inline `checkov:skip` comments remove findings from every report and gate | 21 findings became `✓ No compliance findings!` |
| T-04 | `EUGUARD_NIS2_001` reports Secrets Manager lookups and `random_password` references as hardcoded secrets at CRITICAL | Five secure patterns flagged; one literal missed |
| T-05 | `EUGUARD_NIS2_002` flagged a SOPS-encrypted Secret and `PARTITION_KEY`, and missed `DB_PASS` and a database URL with a password | One scan of three manifests |
| T-06 | Only `eusc-de-east-1` passes the default policy; HIGH severity trips the default gates | Registry and scan |
| T-07 | A bucket with `region = "us-east-1"` and replicas in other regions raise nothing | Scan |
| T-08 | Checkov JSON declaring two parsing errors is reported clean | Scan |
| T-09 | Each scan calls the Prisma Cloud API; `BC_API_KEY` and `PRISMA_API_URL` are passed through | Debug log; parser comparison |
| T-02, T-03 | Two complete failures on Windows | Scans and failing tests |
| T-10, T-11 | A `.venv` symlink or a vendored `*.tf.json` aborts the scan; the repository cannot scan itself | Scans |

Supply-chain and CI items (T-15 to T-20, T-25 to T-27) are improvements to an already good baseline, not signs of neglect. The most useful are hardening the Action's container, gating the release on CI, and adding the Docker base image to Dependabot.

## 4. New functionality

The full list is in **[NEW_FUNC.md](NEW_FUNC.md)**. The three I would build first:

- **[N-01](NEW_FUNC.md#n-01--waiver-file-and-suppression-reporting) Waiver file and suppression reporting.** Accepted findings listed with owner, reason and expiry, in the same style the project already uses for its dependency advisories.
- **[N-02](NEW_FUNC.md#n-02--project-configuration-file) Project configuration file.** Residency policy, excludes, thresholds and overrides in one reviewed place.
- **[N-04](NEW_FUNC.md#n-04--full-compliance-matrix-with-passed-check-evidence) Full compliance matrix.** Passed and failed counts for all fifteen requirements, so the auditor report shows what was evaluated and not only what failed.

After those: residency for Azure, GCP and plan mode with adequacy decisions (N-06), the NIS2 Implementing Regulation and other frameworks (N-07), and baseline mode (N-05).

## 5. What is done well

- **Supply chain.** Runtime and tooling dependencies are hash-locked. The Docker base image is pinned by digest. Every workflow action is pinned by commit, and each commit matches a real upstream tag. Publishing uses OIDC trusted publishing with the build job separated from the publish job. An SBOM is generated and checked against the lock.
- **Advisory exceptions.** Accepted advisories carry an owner, rationale, review date and expiry, and CI fails when one expires or drifts from the workflow.
- **Fail-closed scanning.** Source scans refuse empty targets, parsing errors and mismatched IaC types instead of reporting them clean.
- **Runner isolation.** Checkov runs with `-I`, outside the checkout, with config-file discovery disabled and filter variables stripped. T-01 and T-09 are gaps in an otherwise deliberate design.
- **Report safety.** All HTML is escaped and guideline links are restricted to `http` and `https`. I found no injection path.
- **SARIF paths.** Locations are repository-relative with traversal guarded, and were correct on Windows.
- **Drift guards.** Counts in the documentation are generated from the registries and verified in CI. Example scans are held to recorded baselines.
- **Candour.** Reports state that an absent finding is not evidence of compliance, and unmapped findings are counted, not hidden.

## Notes on this review's files

- `TASKS.md` is listed in `.gitignore` (line 57), so it exists locally but will not be committed, and the links to it will not resolve on GitHub unless that line is removed.
- The review added a `.venv/` directory and `.claude/settings.local.json`. Neither is tracked; the working tree is otherwise unchanged apart from the three review files.

## Follow-up: Dependabot pip PRs and lock-check

Dependabot's `pip` ecosystem (still configured in `.github/dependabot.yml`, weekly, with a 7-day cooldown) bumps the version specifiers and `requirements*` files it finds, but it cannot run `uv pip compile --universal --generate-hashes`. The hashed locks (`requirements.lock`, `requirements-dev.lock`, `requirements-ci.lock`) are generated by `tools/compile-locks.sh`, and the `lock-check` CI job re-runs that script and fails when `git diff` is not empty. A Dependabot pip PR therefore fails `lock-check` until the locks are regenerated.

Fix for one PR (needs `uv` installed; the pinned version is in `requirements-ci.lock`; the script regenerates all three lock files, and uv keeps existing pins unless an input changed):

```
gh pr checkout <PR-number>
./tools/compile-locks.sh
git add requirements*.lock && git commit -m "Regenerate locks" && git push
```

Alternative: remove the `pip` entry from `.github/dependabot.yml` (keep `github-actions` and `docker`) and replace it with a scheduled workflow that runs `./tools/compile-locks.sh --upgrade` and opens a PR with the regenerated locks. That avoids a failing check on every weekly batch, at the cost of maintaining the workflow.
