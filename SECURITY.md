# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Use the repository's
[GitHub private security advisory form](https://github.com/44aayush/tf-eu-guard/security/advisories/new)
instead of opening a public issue or pull request. Do not include exploit
details in public discussions. If the private form is unavailable, open a
minimal public issue requesting a private reporting route without including
the vulnerability details.

Include, where possible:

- the affected version, commit, or installation method;
- the impact and a short description of the attack path;
- a minimal reproduction or sanitized configuration; and
- relevant logs or stack traces with sensitive values removed.

We aim to acknowledge reports within **3 business days**, provide an initial
assessment within **7 business days**, and share status updates at least every
**14 days** while an issue remains open. Fix and disclosure timing depends on
severity and complexity; we will coordinate disclosure with the reporter and
notify them when a fix or mitigation is available.

## Supported versions

tf-eu-guard is a `0.x` (beta) project. Only the latest released minor line,
currently `0.8.x`, receives security fixes, and within it only the latest
patch release. When `0.9.0` is released it becomes the supported line and
`0.8.x` stops receiving fixes. Please update before reporting a
version-specific issue when possible.

| Version | Security support |
| --- | --- |
| Latest released minor line (`0.8.x`; latest patch release only) | Supported |
| Earlier `0.x` lines | Unsupported |
| `main` / unreleased code | Development only; fixes may land here before a release |

## Network behaviour of scans

`tf-eu-guard scan` runs Checkov with `--skip-download`, so a scan makes no
network request by default (Checkov would otherwise call the Prisma Cloud
platform for guideline metadata). `--online` allows that request. In both
modes every `BC_*`, `PRISMA_*` and `CKV_IGNORE*` environment variable is
removed from Checkov's environment, so platform API keys are never used and
no results are uploaded. Scanned code is only read, never executed, and
remote Terraform modules are not downloaded.

## Safe handling of credentials and live infrastructure

- Never include passwords, API tokens, private keys, cloud credentials,
  kubeconfigs, Terraform state, personal data, or other secrets in a report.
- Redact logs and configuration, and use a minimal reproducible example with
  synthetic values.
- Test only in an isolated environment that you own or are authorized to use;
  do not probe, modify, or run proof-of-concept code against live infrastructure.
- If a credential may have been exposed, revoke or rotate it immediately, then
  report the incident through the private channel with only redacted details.
