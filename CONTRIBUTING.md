# Contributing to tf-eu-guard

Thanks for your interest in improving EU infrastructure compliance tooling!

## Ways to contribute

1. **Registry expansion** — map more Checkov checks to NIS2/GDPR articles (the highest-value contribution)
2. **New custom checks** — EU-specific patterns upstream Checkov doesn't cover
3. **Report improvements** — better visualizations, export formats
4. **Bug fixes & docs**

For registry expansion, please **open an issue first** describing the checks you
want to map — this avoids duplicate work and lets us discuss article choices
before you invest time in a PR.

## Proposing a new mapping

The registry is split per *namespace* in `tf_eu_guard/mapping/` — which today
means cloud provider for Terraform checks, plus a separate file for the
Kubernetes check namespace:

| File | Namespace |
|------|-----------|
| `registry-aws.yaml` | AWS (116 mappings — covers Terraform source *and* plan JSON, since the same `CKV_AWS_*` IDs fire in both modes) |
| `registry-azure.yaml` | Azure (23 mappings) |
| `registry-gcp.yaml` | GCP (22 mappings) |
| `registry-kubernetes.yaml` | Kubernetes `CKV_K8S_*` (24 mappings) |

Check IDs are globally unique keys, so a mapping works for every IaC type its
check ID fires under — only genuinely disjoint namespaces (like K8s) get their
own file. When adding a new IaC target, diff the IDs that actually fire
against the registry and author only the gap (see
`docs/DECISIONS.md` #8–9).

> The mapping counts in this table, the README and `docs/` are verified
> against the registry files by `tools/check_doc_counts.py` (CI runs it, and
> so does the test suite). Don't hand-type counts anywhere else — if you need
> to cite one, expect the check to enforce it.

### Schema

Every entry must have these fields (validated in CI by
`tf_eu_guard.mapping.loader.validate_all`):

```yaml
CKV_AWS_18:
  check_name: "Ensure the S3 bucket has access logging enabled"
  articles:                          # at least one; framework must be NIS2 or GDPR
    - framework: NIS2
      article: "Art. 21(2)(b)"       # format: "Art. N(P)(letter)" or "Art. N"
      title: "Incident handling"
    - framework: GDPR
      article: "Art. 32(1)(b)"
      title: "Confidentiality, integrity and availability"
  risk: "Plain-language explanation citing the specific legal requirement."
  remediation: |
    resource "aws_s3_bucket" "example" {
      # copy-pasteable Terraform
    }
  severity: MEDIUM                   # CRITICAL | HIGH | MEDIUM | LOW
```

### Quality bar

- **Risk explanations must cite specific legal text.** Name the article and the
  requirement it imposes; don't just restate the check. Cross-check sub-point
  letters against the directive/regulation (see `docs/nis2-mapping.md` and
  `docs/gdpr-mapping.md` for verified citations).
- **Remediation must be copy-paste Terraform code**, not a prose description.
- **Verify the Checkov ID against a real scan.** Run
  `checkov -d <dir> --framework terraform --quiet -o json` against a stack that
  triggers the check and confirm the ID appears. A mispredicted ID means a
  silent miss — the finding will never be enriched. (The test suite enforces
  that every registry ID exists in the installed Checkov.)

### Test requirements

Add a fixture that triggers your new check and assert it appears in the output:

1. Add or extend a Terraform file under `examples/` that fails the check.
2. Add an assertion in `tests/` that the check ID is present in the enriched
   output of that example (see `tests/test_registry.py` for patterns).

Run the full suite before opening a PR:

```bash
bash install_and_test.sh
```

(creates a venv, installs dev extras, runs pytest with coverage, and smoke-tests
a scan of `examples/vulnerable-aws/`).

## Smoke checks (regression guard)

A past bug (commit `c7e68f6`) shipped a broken `terraform_plan` scan path that
silently returned 0 findings while unit tests and CI both stayed green — the
CI smoke test scanned a hand-shaped fixture instead of the real example. To
keep that class of silent failure from recurring, the expected mapped-finding
counts for every vulnerable/compliant example pair live in
**`tools/smoke_baselines.json`** — a single source of truth read by CI
(`.github/workflows/ci.yml`), by `tools/smoke_check.py`, and by the local
Claude Code hook (below).

Run the smoke check for one IaC type (takes seconds; scope to one type,
not `all`, when iterating):

```bash
python3 tools/smoke_check.py --iac-type terraform
python3 tools/smoke_check.py --iac-type terraform_plan
python3 tools/smoke_check.py --iac-type kubernetes
```

It exits `0` when counts match the baseline, `2` when a vulnerable example
returns too few findings or a compliant one returns any (the message includes
the actual and expected counts), and `1` on unexpected errors. It also prints
a non-fatal note when a count is above baseline — if the change is
intentional, update `tools/smoke_baselines.json` in the same PR.

When adding a new IaC type or example fixture:

1. add its expected count to `tools/smoke_baselines.json`,
2. extend the path→iac-type mapping in `tools/hook_smoke_dispatch.py`
   (examples are mapped by their directory name; registries and custom
   checks by their file location),
3. wire it into the CI smoke steps —

— all in the same commit. The failure mode of skipping this is the same
silent-0 the guard exists to catch.

### Claude Code hook (for contributors using Claude Code)

The repo ships a `PostToolUse` hook (`.claude/settings.json`) that runs
`tools/hook_smoke_dispatch.py` after every `Edit`/`Write`/`MultiEdit`. The
dispatcher maps the edited file path to the IaC types it can affect
(`cli.py`/`checkov_runner.py` → all types; `registry-kubernetes.yaml` →
kubernetes only; `examples/vulnerable-aws-plan/**` → terraform_plan; etc.)
and runs only those smoke checks. A failing check exits `2`, which surfaces
the failure message in the Claude Code session even though the edit already
landed. Unrelated edits (README, tests, docs) trigger nothing, keeping the
hook fast enough to not train you to ignore it.

If you don't use Claude Code, running `tools/smoke_check.py` by hand (or
relying on CI) gives you the same guard — the hook is just automation around
the same script.

## Proposing a custom check

Custom `EUGUARD_*` checks live in `tf_eu_guard/checks/`. They must:
- target an EU-specific requirement stock Checkov doesn't cover,
- have a registry mapping (severity, articles, risk, remediation), and
- fire against a fixture in `examples/`.

## Labels

Look for `good first issue` on the issue tracker for entry-point tasks — mostly
registry expansion where the legal reasoning is already agreed.
