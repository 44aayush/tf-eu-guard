# Waiver file

A waiver is a reviewed acceptance of one mapped finding. A waived finding no longer
counts toward `--fail-on-severity`, `--fail-on-any` or `--fail-on-suppressed`, but it
stays visible: every report (dev terminal, dev/security/auditor HTML, JSON, SARIF)
lists it with its owner, reason and expiry, and the requirement matrix counts it as
waived.

## File

`--waivers FILE`, or `.tf-eu-guard-waivers.yaml` in the scan root (the scanned
directory, or the parent directory of a Terraform plan file). Discovery happens only
for source scans; with `--checkov-json` and no `--waivers` nothing is read. An explicit
`--config FILE` also disables discovery (so a trusted config cannot be undercut by a
waiver file in the scanned code); `--waivers` and the config's `waivers:` key still apply.

```yaml
schema_version: 1
waivers:
  - check_id: CKV_AWS_18          # required, case-sensitive
    resource: aws_s3_bucket.logs  # required, exact Checkov resource address
    file: "modules/**/*.tf"       # optional, glob on file_path (leading "/" stripped, POSIX separators)
    owner: platform-team          # required, non-empty
    reason: Access logs bucket; logging it would recurse.  # required, non-empty
    expires: 2027-03-31           # required, YAML date or ISO string
```

Unknown keys, missing required keys, duplicate keys, a `schema_version` other than 1
or an unparsable date exit 2. A `--waivers` file that does not exist also exits 2.

## Matching

A waiver matches a finding when check ID and resource are equal and, if `file` is
set, the glob matches the finding's file path (`fnmatch`; `*` also crosses `/`, so `**`
works). A waiver applies to active findings and to findings suppressed by an inline
`checkov:skip`; a reviewed waiver on an inline-suppressed finding is the authorisation
`--fail-on-suppressed` asks for. Unmapped findings cannot be waived: waivers are
reviewed acceptances of mapped compliance gaps.

A waiver is valid through its `expires` date. After that the finding is active again
and stderr says `Waiver expired on <date>: <check_id> <resource> (owner <owner>)`.
stderr also reports `N finding(s) waived by <path>` and warns about waivers that
matched nothing.

## Trust

The waiver file in the scanned checkout can be edited by anyone who can edit the code.
See [limitations](limitations.md).
