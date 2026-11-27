"""Plan-mode residency against a real Terraform plan (REVIEW.md section 6).

The fixture has no region in source; the region arrives through AWS_REGION at
plan time, so only a plan scan can see it.
"""

import boto3
import pytest

from tf_eu_guard import scan

FIXTURE = "no-provider-region"

# botocore (a locked Checkov dependency) still calls datetime.utcnow() when signing.
pytestmark = pytest.mark.filterwarnings("ignore:datetime.datetime.utcnow:DeprecationWarning")


def test_env_region_is_caught_in_plan_mode(make_stack):
    plan = make_stack(FIXTURE, "us-east-1").plan_json()
    result = scan(plan, iac_type="terraform_plan", no_config=True)
    ids = {f.check_id for f in result.findings}
    assert {"EUGUARD_POLICY_002", "EUGUARD_GDPR_003"} <= ids


def test_s3_public_access_block_ground_truth(make_stack, endpoint):
    stack = make_stack(FIXTURE, "us-east-1")
    plan = stack.plan_json()
    stack.apply()
    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        config = s3.get_public_access_block(Bucket="tf-eu-guard-emulator-data")
        flags = config["PublicAccessBlockConfiguration"]
        assert flags == {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
        ids = {f.check_id for f in scan(plan, iac_type="terraform_plan", no_config=True).findings}
        missing = {f"CKV_AWS_{n}" for n in range(53, 57)} - ids
        assert not missing, f"insecure state read back but no finding for {sorted(missing)}"
    finally:
        stack.destroy()
