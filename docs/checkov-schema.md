# Checkov JSON Schema Documentation

**Date**: 2026-08-23  
**Checkov Version**: 3.3.13  
**Source**: Scan of vulnerable TF files at `/home/aayush/Desktop/tf-eu-guard/tf/`

## Top-Level Structure

```json
{
  "check_type": "terraform",
  "results": {
    "failed_checks": [...],
    "passed_checks": [...],
    "skipped_checks": [...],
    "parsing_errors": [...]
  },
  "summary": { ... }
}
```

## Failed Check Object Structure

Each entry in `results.failed_checks[]` contains:

| Field | Type | Example | Used in tf-eu-guard |
|-------|------|---------|---------------------|
| `check_id` | string | "CKV_AWS_273" | ✅ Primary key for registry mapping |
| `bc_check_id` | string | "BC_AWS_IAM_77" | ❌ Not used |
| `check_name` | string | "Ensure access is controlled through SSO..." | ✅ Displayed in reports |
| `resource` | string | "aws_iam_user.admin" | ✅ Displayed in reports |
| `file_path` | string | "/iam.tf" | ✅ File grouping in dev report |
| `file_abs_path` | string | "/home/aayush/.../iam.tf" | ❌ Not used |
| `file_line_range` | [int, int] | [20, 27] | ✅ Line reference in reports |
| `guideline` | string | "https://docs.prismacloud.io/..." | ✅ External reference link |
| `check_result` | object | `{"result": "FAILED", ...}` | ❌ Not used (status is implicit) |
| `code_block` | array/null | Code snippet | ⚠️ Often null, not reliable |
| `severity` | string/null | "HIGH" / null | ⚠️ Often null in 3.3.13 |
| `entity_tags` | object | `{"Name": "..."}` | ❌ Not used |
| `breadcrumbs` | object | Variable tracing | ❌ Not used |

## Schema Compatibility with tf_eu_guard

### ✅ Compatible Fields (Used)
Our `checkov_runner.extract_failed_checks()` function expects:
```python
{
    "check_id": str,       # ✓ Present
    "check_name": str,     # ✓ Present
    "resource": str,       # ✓ Present
    "file_path": str,      # ✓ Present
    "file_line_range": [int, int],  # ✓ Present
    "guideline": str       # ✓ Present (can be null)
}
```

**Result**: ✅ All required fields are present and match our expectations.

### ⚠️ Severity Handling

**Observation**: The `severity` field is often `null` in Checkov 3.3.13 output.

**Impact**: We must define severity in our `registry-aws.yaml` mappings, not rely on Checkov's severity.

**Action**: Our mapping format already includes a `severity` field:
```yaml
CKV_AWS_273:
  severity: HIGH  # ✓ We define this ourselves
```

## Example Finding (First Failed Check)

```json
{
  "check_id": "CKV_AWS_273",
  "check_name": "Ensure access is controlled through SSO and not AWS IAM defined users",
  "resource": "aws_iam_user.admin",
  "file_path": "/iam.tf",
  "file_line_range": [20, 27],
  "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-iam-policies/bc-aws-273"
}
```

## Validation Summary

| Component | Status | Notes |
|-----------|--------|-------|
| JSON parsing | ✅ Valid | Clean JSON structure |
| Required fields | ✅ Present | All fields we need exist |
| Field types | ✅ Correct | Strings, arrays match expectations |
| Severity field | ⚠️ Unreliable | Often null, define in registry |
| Schema stability | ✅ Stable | Matches Checkov documentation |

## Next Steps (Phase 1.4)

1. ✅ Schema verified - matches `checkov_runner.py` expectations
2. 🔄 Update `extract_failed_checks()` if needed (likely no changes required)
3. 🔄 Test end-to-end pipeline with one registry mapping
4. 🔄 Document any schema quirks discovered during testing

## Statistics from Scan

*To be populated after running count query on checkov-raw-output.json*

- Total failed checks: [TBD]
- Total passed checks: [TBD]
- Total skipped checks: [TBD]
- Unique check IDs found: [TBD]

---

**Status**: Schema verification complete ✓  
**Blockers**: None  
**Ready for**: Phase 1.4 - End-to-end pipeline test
