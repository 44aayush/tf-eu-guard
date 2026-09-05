# vulnerable-aws-plan — Terraform plan-JSON fixture

`plan.json` is the `terraform show -json` output of a plan for
`examples/vulnerable-aws/`, generated offline (provider skip flags + dummy
credentials, nothing applied). Used by CI and tests to exercise
`--iac-type terraform_plan` (scan the file directly: `tf-eu-guard scan
plan.json --iac-type terraform_plan`). Plan-mode findings report
`file_line_range: [0, 0]` because the whole plan is one JSON line.

## Regenerate

```bash
cp -r ../vulnerable-aws /tmp/tfplan-work && cd /tmp/tfplan-work
# add skip_credentials_validation / skip_requesting_account_id /
# skip_metadata_api_check to the provider block, then:
export AWS_ACCESS_KEY_ID=fake AWS_SECRET_ACCESS_KEY=fake AWS_REGION=eu-west-1
terraform init -input=false && terraform plan -input=false -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
```
